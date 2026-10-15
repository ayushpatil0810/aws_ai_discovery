"""Automated cleanup script to tear down demo resources created by create_demo_resources.py."""

import os
import sys
import logging

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from botocore.exceptions import ClientError
from src.config import Settings
from src.discovery.aws_session import AWSSessionManager

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("cleanup_resources")


def cleanup_demo_resources():
    settings = Settings()
    session_mgr = AWSSessionManager(settings)
    session = session_mgr.get_session()
    
    identity = session_mgr.validate_credentials()
    account_id = identity["account_id"]
    region = settings.aws_default_region or "us-east-1"
    
    logger.info(f"Connected to AWS Account [{account_id}] in Region [{region}] for cleanup")

    # 1. Delete Bedrock Guardrail
    bedrock = session.client("bedrock", region_name=region)
    try:
        resp = bedrock.list_guardrails()
        for g in resp.get("guardrails", []):
            if g.get("name") == "EnterpriseAIGuardrail":
                gid = g.get("id")
                logger.info(f"Deleting Bedrock Guardrail [{gid}]...")
                bedrock.delete_guardrail(guardrailIdentifier=gid)
                logger.info(f" Deleted Bedrock Guardrail: {gid}")
    except ClientError as e:
        logger.warning(f"Error deleting Bedrock Guardrail: {e}")

    # 2. Delete Polly Lexicon
    polly = session.client("polly", region_name=region)
    for lex in ["AITermLexicon", "AITerminologyLexicon"]:
        try:
            polly.delete_lexicon(Name=lex)
            logger.info(f" Deleted Polly Lexicon: {lex}")
        except ClientError:
            pass

    # 3. Delete API Gateways
    apigw = session.client("apigatewayv2", region_name=region)
    try:
        apis = apigw.get_apis().get("Items", [])
        for api in apis:
            name = api.get("Name", "")
            if name in ["ai-model-inference-gateway", "openai-gpt4-proxy-gateway"]:
                aid = api.get("ApiId")
                logger.info(f"Deleting API Gateway [{name}] ({aid})...")
                apigw.delete_api(ApiId=aid)
                logger.info(f" Deleted API Gateway: {name}")
    except ClientError as e:
        logger.warning(f"Error deleting API Gateways: {e}")

    # 4. Delete Lambda Functions
    lambda_client = session.client("lambda", region_name=region)
    for fn in ["customer-support-ai-bot", "rag-knowledge-search-service"]:
        try:
            logger.info(f"Deleting Lambda [{fn}]...")
            lambda_client.delete_function(FunctionName=fn)
            logger.info(f" Deleted Lambda: {fn}")
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                logger.info(f" Lambda {fn} not found, skipping.")
            else:
                logger.warning(f"Error deleting Lambda {fn}: {e}")

    # 5. Delete SageMaker Model
    sagemaker = session.client("sagemaker", region_name=region)
    model_name = "financial-sentiment-classifier-v1"
    try:
        logger.info(f"Deleting SageMaker Model [{model_name}]...")
        sagemaker.delete_model(ModelName=model_name)
        logger.info(f" Deleted SageMaker Model: {model_name}")
    except ClientError as e:
        logger.warning(f"Error deleting SageMaker model {model_name}: {e}")

    # 6. Delete Step Functions Workflow
    sfn = session.client("stepfunctions", region_name=region)
    sfn_name = "ai-document-intelligence-workflow"
    try:
        state_machine_arn = f"arn:aws:states:{region}:{account_id}:stateMachine:{sfn_name}"
        logger.info(f"Deleting Step Functions State Machine [{sfn_name}]...")
        sfn.delete_state_machine(stateMachineArn=state_machine_arn)
        logger.info(f" Deleted Step Functions: {sfn_name}")
    except ClientError as e:
        logger.warning(f"Error deleting Step Functions: {e}")

    # 7. Delete IAM Role
    iam = session.client("iam")
    role_name = "AIDiscoveryDemoExecutionRole"
    try:
        try:
            iam.detach_role_policy(
                RoleName=role_name,
                PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
            )
        except Exception:
            pass
        logger.info(f"Deleting IAM Execution Role [{role_name}]...")
        iam.delete_role(RoleName=role_name)
        logger.info(f" Deleted IAM Role: {role_name}")
    except ClientError as e:
        logger.warning(f"Error deleting IAM Role: {e}")

    logger.info("\n All demonstration resources cleaned up successfully!")


if __name__ == "__main__":
    cleanup_demo_resources()
