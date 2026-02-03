import json
import boto3
import logging
from vuln_lookup import lookup_vulnerabilities
from enrichment import enrich_vulnerabilities
from bedrock_analyzer import analyze_with_bedrock

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# AWS clients
s3_client = boto3.client('s3')


def lambda_handler(event, context):
    """
    Triggered when an SBOM file is uploaded to the input S3 bucket.
    Parses SBOM, looks up vulnerabilities, enriches with EPSS/KEV,
    analyzes with Bedrock, and writes report to output bucket.
    """
    
    # Get bucket and file info from the S3 event
    record = event['Records'][0]
    bucket_name = record['s3']['bucket']['name']
    object_key = record['s3']['object']['key']
    
    logger.info(f"Processing file: s3://{bucket_name}/{object_key}")
    
    try:
        # Step 1: Download the SBOM file from S3
        response = s3_client.get_object(Bucket=bucket_name, Key=object_key)
        sbom_content = response['Body'].read().decode('utf-8')
        sbom_data = json.loads(sbom_content)
        
        # Step 2: Parse components from the SBOM
        components = parse_sbom(sbom_data)
        logger.info(f"Extracted {len(components)} components")
        
        # Step 3: Look up vulnerabilities from OSV
        components = lookup_vulnerabilities(components)
        
        # Step 4: Enrich with EPSS and KEV
        components = enrich_vulnerabilities(components)
        
        # Step 5: Analyze with Bedrock LLM
        components = analyze_with_bedrock(components)
        
        # Step 6: Generate summary
        summary = generate_summary(components)
        logger.info(f"Summary: {summary['total_vulns']} vulnerabilities, {summary['critical']} critical")
        
        # Step 7: Write report to output bucket
        report = {
            'source_file': f"s3://{bucket_name}/{object_key}",
            'scan_timestamp': context.aws_request_id,
            'summary': summary,
            'components': components
        }
        
        output_bucket = bucket_name.replace('-input-', '-output-')
        output_key = object_key.replace('.json', '-report.json')
        
        s3_client.put_object(
            Bucket=output_bucket,
            Key=output_key,
            Body=json.dumps(report, indent=2),
            ContentType='application/json'
        )
        logger.info(f"Report written to s3://{output_bucket}/{output_key}")
        
        # Step 8: Log results
        for comp in components:
            for vuln in comp.get('vulnerabilities', []):
                logger.info(
                    f"{comp['name']}@{comp['version']} - "
                    f"{vuln.get('cve_id', vuln.get('id', 'unknown'))}: "
                    f"priority={vuln.get('contextual_priority', 'unknown')}, "
                    f"remediation={vuln.get('remediation', 'N/A')}"
                )
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'SBOM processed successfully',
                'component_count': len(components),
                'summary': summary,
                'report_location': f"s3://{output_bucket}/{output_key}"
            })
        }
        
    except Exception as e:
        logger.error(f"Error processing SBOM: {str(e)}")
        raise


def parse_sbom(sbom_data):
    """
    Extracts components from a CycloneDX SBOM.
    """
    
    components = []
    
    for component in sbom_data.get('components', []):
        components.append({
            'name': component.get('name', 'unknown'),
            'version': component.get('version', 'unknown'),
            'purl': component.get('purl', ''),
            'type': component.get('type', 'library')
        })
    
    return components


def generate_summary(components):
    """
    Generate a summary of vulnerabilities found.
    """
    
    total_vulns = 0
    critical = 0
    high = 0
    in_kev = 0
    high_epss = 0
    
    for comp in components:
        for vuln in comp.get('vulnerabilities', []):
            total_vulns += 1
            
            priority = vuln.get('contextual_priority', 'low')
            if priority == 'critical':
                critical += 1
            elif priority == 'high':
                high += 1
            
            if vuln.get('in_kev'):
                in_kev += 1
            
            if vuln.get('epss', 0) > 0.1:
                high_epss += 1
    
    return {
        'total_vulns': total_vulns,
        'critical': critical,
        'high': high,
        'in_kev': in_kev,
        'high_epss': high_epss
    }