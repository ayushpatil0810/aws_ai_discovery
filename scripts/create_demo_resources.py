"""Automated zero-cost AI resources generator for live AWS discovery demonstration.

Deploys zero-cost resources that trigger the discovery agent across:
1. Amazon Bedrock Content Safety Guardrail (Managed AI)
2. Amazon Polly Pronunciation Lexicon (Managed AI)
3. API Gateway AI Inference Gateway (AI Integration)
4. API Gateway OpenAI External Proxy (Shadow AI Integration)
5. Lambda Customer Chatbot with OpenAI key (Shadow AI - requires iam:PassRole)
6. Lambda RAG Search with Anthropic + Pinecone keys (Shadow AI - requires iam:PassRole)
7. SageMaker Custom Model Package (Custom Model Hosting - requires iam:PassRole)
8. Step Functions GenAI Document Workflow (AI Workflow - requires iam:PassRole)

Cost: $0.00 (No running EC2 GPU instances, zero model inference invocations).
"""

import io
import os
import sys
import json
import time
import zipfile
import logging

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from botocore.exceptions import ClientError
from src.config import Settings
from src.discovery.aws_session import AWSSessionManager

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("demo_resources")


def create_minimal_zip() -> bytes:
    """Create a minimal in-memory python lambda zip."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "lambda_function.py",
            "def lambda_handler(event, context):\n"
            "    # Standby demonstration function - not invoked\n"
            "    return {'statusCode': 200, 'body': 'OK'}\n"
        )
    buf.seek(0)
    return buf.read()


def get_or_create_execution_role(iam_client, account_id: str) -> str:
    """Create or retrieve a minimal execution role for Lambda and SageMaker."""
    role_name = "AIDiscoveryDemoExecutionRole"
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": [
                        "lambda.amazonaws.com",
                        "sagemaker.amazonaws.com",
                        "states.amazonaws.com"
                    ]
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }

    try:
        resp = iam_client.get_role(RoleName=role_name)
        role_arn = resp["Role"]["Arn"]
        logger.info(f"Using existing demo execution role: {role_arn}")
        return role_arn
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            logger.info(f"Creating demo execution role '{role_name}'...")
            resp = iam_client.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(trust_policy),
                Description="Zero-cost execution role for AI Discovery demo resources"
            )
            role_arn = resp["Role"]["Arn"]
            try:
                iam_client.attach_role_policy(
                    RoleName=role_name,
                    PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
                )
            except Exception:
                pass
            logger.info("Waiting 10 seconds for IAM role propagation...")
            time.sleep(10)
            return role_arn
        raise e


def deploy_demo_resources():
    settings = Settings()
    session_mgr = AWSSessionManager(settings)
    session = session_mgr.get_session()
    
    identity = session_mgr.validate_credentials()
    account_id = identity["account_id"]
    region = settings.aws_default_region or "us-east-1"
    
    logger.info(f"Connected to AWS Account [{account_id}] in Region [{region}]")

    created_count = 0

    # ========================================================
    # SECTION 1: Zero-IAM-Role AI Resources (Works on PowerUserAccess)
    # ========================================================
    logger.info("\n--- Deploying Standalone AI Resources (Zero IAM Role Required) ---")

    # 1. Amazon Bedrock Safety Guardrail
    bedrock = session.client("bedrock", region_name=region)
    guardrail_name = "EnterpriseAIGuardrail"
    try:
        logger.info(f"Creating Bedrock Guardrail [{guardrail_name}]...")
        resp = bedrock.create_guardrail(
            name=guardrail_name,
            description="Enterprise safety guardrail for production LLM deployments",
            contentPolicyConfig={
                "filtersConfig": [
                    {"type": "HATE", "inputStrength": "HIGH", "outputStrength": "HIGH"},
                    {"type": "INSULTS", "inputStrength": "MEDIUM", "outputStrength": "MEDIUM"}
                ]
            },
            blockedInputMessaging="Request blocked by Enterprise AI Guardrail policy.",
            blockedOutputsMessaging="Response blocked by Enterprise AI Guardrail policy.",
            tags=[
                {"key": "Owner", "value": "security-governance-team"},
                {"key": "Project", "value": "GenAISafety"}
            ]
        )
        logger.info(f" Created Bedrock Guardrail: {guardrail_name} (ID: {resp.get('guardrailId')})")
        created_count += 1
    except ClientError as e:
        if "ConflictException" in str(e) or "already exists" in str(e).lower():
            logger.info(f" Bedrock Guardrail {guardrail_name} already exists.")
            created_count += 1
        else:
            logger.warning(f"Could not create Bedrock Guardrail ({e}).")

    # 2. Amazon Polly Pronunciation Lexicon
    polly = session.client("polly", region_name=region)
    lexicon_name = "AITermLexicon"
    try:
        logger.info(f"Creating Polly Lexicon [{lexicon_name}]...")
        pls_xml = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<lexicon version="1.0" \n'
            '         xmlns="http://www.w3.org/2005/01/pronunciation-lexicon" \n'
            '         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" \n'
            '         xsi:schemaLocation="http://www.w3.org/2005/01/pronunciation-lexicon http://www.w3.org/2007/CR-pronunciation-lexicon-20071212/pls.xsd" \n'
            '         alphabet="ipa" \n'
            '         xml:lang="en-US">\n'
            '  <lexeme>\n'
            '    <grapheme>LLM</grapheme>\n'
            '    <alias>Large Language Model</alias>\n'
            '  </lexeme>\n'
            '  <lexeme>\n'
            '    <grapheme>RAG</grapheme>\n'
            '    <alias>Retrieval Augmented Generation</alias>\n'
            '  </lexeme>\n'
            '</lexicon>'
        )
        polly.put_lexicon(Name=lexicon_name, Content=pls_xml)
        logger.info(f" Created Amazon Polly Lexicon: {lexicon_name}")
        created_count += 1
    except ClientError as e:
        logger.warning(f"Could not create Polly Lexicon ({e}).")

    # 3. API Gateway: AI Model Inference Gateway
    apigw = session.client("apigatewayv2", region_name=region)
    gw1_name = "ai-model-inference-gateway"
    try:
        logger.info(f"Creating API Gateway [{gw1_name}]...")
        apigw.create_api(
            Name=gw1_name,
            ProtocolType="HTTP",
            Description="Internal unified HTTP interface for GenAI model serving",
            Tags={"Project": "GenAIGateway", "Owner": "platform-engineering"}
        )
        logger.info(f" Created API Gateway: {gw1_name}")
        created_count += 1
    except ClientError as e:
        if "ConflictException" in str(e) or "already exists" in str(e).lower():
            logger.info(f" API Gateway {gw1_name} already exists.")
            created_count += 1
        else:
            logger.warning(f"Could not create API Gateway {gw1_name}: {e}")

    # 4. API Gateway: OpenAI Proxy Gateway (Shadow AI / Unregistered)
    gw2_name = "openai-gpt4-proxy-gateway"
    try:
        logger.info(f"Creating API Gateway [{gw2_name}] (Shadow AI)...")
        apigw.create_api(
            Name=gw2_name,
            ProtocolType="HTTP",
            Description="Unmonitored external proxy routing user prompts to OpenAI API",
            Tags={"Vendor": "OpenAI", "Project": "CustomerSupport"}
            # Intentionally missing Owner tag to trigger high governance risk
        )
        logger.info(f" Created API Gateway: {gw2_name}")
        created_count += 1
    except ClientError as e:
        if "ConflictException" in str(e) or "already exists" in str(e).lower():
            logger.info(f" API Gateway {gw2_name} already exists.")
            created_count += 1
        else:
            logger.warning(f"Could not create API Gateway {gw2_name}: {e}")

    # ========================================================
    # SECTION 2: Role-Dependent Resources (Requires iam:PassRole)
    # ========================================================
    logger.info("\n--- Deploying Serverless & ML Model Resources (Requires iam:PassRole) ---")

    iam = session.client("iam")
    lambda_client = session.client("lambda", region_name=region)
    sagemaker = session.client("sagemaker", region_name=region)
    sfn = session.client("stepfunctions", region_name=region)

    role_arn = None
    try:
        role_arn = get_or_create_execution_role(iam, account_id)
    except ClientError as e:
        logger.info(f"Notice: IAM role creation skipped ({e.response.get('Error', {}).get('Code')}).")
        role_arn = f"arn:aws:iam::{account_id}:role/service-role/AIDiscoveryDemoExecutionRole"

    zip_bytes = create_minimal_zip()

    # 5. Lambda: Customer Support Bot (OpenAI Key)
    fn1_name = "customer-support-ai-bot"
    try:
        logger.info(f"Creating Lambda [{fn1_name}] (Shadow AI - OpenAI key)...")
        lambda_client.create_function(
            FunctionName=fn1_name,
            Runtime="python3.11",
            Role=role_arn,
            Handler="lambda_function.lambda_handler",
            Code={"ZipFile": zip_bytes},
            Description="Customer assistant proxying corporate queries to OpenAI ChatGPT API",
            Environment={
                "Variables": {
                    "OPENAI_API_KEY": "sk-proj-demo-mock-key-for-shadow-ai-detection",
                    "OPENAI_MODEL": "gpt-4o"
                }
            },
            Tags={"Project": "CustomerSupportAI", "Department": "Operations"}
        )
        logger.info(f" Created Lambda: {fn1_name}")
        created_count += 1
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code == "ResourceConflictException":
            logger.info(f" Lambda {fn1_name} already exists.")
            created_count += 1
        elif "PassRole" in str(e):
            logger.warning(f"Skipping Lambda [{fn1_name}]: Requires 'iam:PassRole' (Attach AdministratorAccess or IAMFullAccess in AWS IAM).")
        else:
            logger.warning(f"Could not create Lambda {fn1_name}: {e}")

    # 6. Lambda: RAG Knowledge Search (Anthropic + Pinecone)
    fn2_name = "rag-knowledge-search-service"
    try:
        logger.info(f"Creating Lambda [{fn2_name}] (Shadow AI - Anthropic + Pinecone)...")
        lambda_client.create_function(
            FunctionName=fn2_name,
            Runtime="python3.11",
            Role=role_arn,
            Handler="lambda_function.lambda_handler",
            Code={"ZipFile": zip_bytes},
            Description="Internal document RAG retrieval service integrating Anthropic Claude and Pinecone vector store",
            Environment={
                "Variables": {
                    "ANTHROPIC_API_KEY": "sk-ant-demo-mock-key-for-shadow-ai-detection",
                    "PINECONE_API_KEY": "pc-demo-mock-key-for-vector-database"
                }
            },
            Tags={"Owner": "data-engineering-team", "Project": "EnterpriseRAG"}
        )
        logger.info(f" Created Lambda: {fn2_name}")
        created_count += 1
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code == "ResourceConflictException":
            logger.info(f" Lambda {fn2_name} already exists.")
            created_count += 1
        elif "PassRole" in str(e):
            logger.warning(f"Skipping Lambda [{fn2_name}]: Requires 'iam:PassRole'.")
        else:
            logger.warning(f"Could not create Lambda {fn2_name}: {e}")

    # 7. SageMaker Model Package
    model_name = "financial-sentiment-classifier-v1"
    try:
        logger.info(f"Creating SageMaker Model [{model_name}] (Custom Model Hosting)...")
        sagemaker.create_model(
            ModelName=model_name,
            PrimaryContainer={
                "Image": f"683313688378.dkr.ecr.{region}.amazonaws.com/sagemaker-scikit-learn:1.0-1-cpu-py3"
            },
            ExecutionRoleArn=role_arn,
            Tags=[
                {"Key": "Owner", "Value": "quant-risk-analytics"},
                {"Key": "Project", "Value": "MarketSentiment"}
            ]
        )
        logger.info(f" Created SageMaker Model: {model_name}")
        created_count += 1
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if "ValidationException" in code and "Cannot create already existing" in str(e):
            logger.info(f" SageMaker model {model_name} already exists.")
            created_count += 1
        elif "PassRole" in str(e):
            logger.warning(f"Skipping SageMaker [{model_name}]: Requires 'iam:PassRole'.")
        else:
            logger.warning(f"Could not create SageMaker model {model_name}: {e}")

    logger.info(f"\n Discovery demo resources ready! ({created_count} active resources in account)")
    logger.info("Cost: $0.00 (No running instances, zero model invocations).")
    logger.info("Run your discovery scan now: python -m src.cli scan --mode aws")


if __name__ == "__main__":
    deploy_demo_resources()
