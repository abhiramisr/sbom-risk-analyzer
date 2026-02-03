import json
import urllib.request
import urllib.error
import logging

logger = logging.getLogger()


def query_osv(purl):
    """
    Query OSV.dev API for vulnerabilities affecting a package.
    
    Args:
        purl: Package URL (e.g., "pkg:npm/lodash@4.17.15")
    
    Returns:
        List of vulnerability dicts with cve_id, cvss, description
    """
    
    url = "https://api.osv.dev/v1/query"
    
    payload = json.dumps({
        "package": {
            "purl": purl
        }
    }).encode('utf-8')
    
    headers = {
        "Content-Type": "application/json"
    }
    
    try:
        req = urllib.request.Request(url, data=payload, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode('utf-8'))
        
        vulnerabilities = []
        
        for vuln in data.get('vulns', []):
            # Extract CVE ID if available
            cve_id = None
            for alias in vuln.get('aliases', []):
                if alias.startswith('CVE-'):
                    cve_id = alias
                    break
            
            # Extract CVSS score if available
            cvss_score = None
            severity = vuln.get('severity', [])
            for sev in severity:
                if sev.get('type') == 'CVSS_V3':
                    cvss_score = sev.get('score')
                    break
            
            vulnerabilities.append({
                'id': vuln.get('id'),
                'cve_id': cve_id,
                'summary': vuln.get('summary', 'No description available'),
                'cvss': cvss_score,
                'published': vuln.get('published'),
                'severity': vuln.get('database_specific', {}).get('severity', 'UNKNOWN')
            })
        
        return vulnerabilities
        
    except urllib.error.URLError as e:
        logger.error(f"OSV API error for {purl}: {str(e)}")
        return []
    except Exception as e:
        logger.error(f"Unexpected error querying OSV for {purl}: {str(e)}")
        return []


def lookup_vulnerabilities(components):
    """
    Look up vulnerabilities for a list of components.
    
    Args:
        components: List of dicts with name, version, purl
    
    Returns:
        List of components enriched with vulnerability data
    """
    
    enriched = []
    
    for comp in components:
        purl = comp.get('purl')
        
        if not purl:
            logger.warning(f"No purl for component {comp.get('name')}, skipping")
            comp['vulnerabilities'] = []
            enriched.append(comp)
            continue
        
        vulns = query_osv(purl)
        comp['vulnerabilities'] = vulns
        
        logger.info(f"{comp['name']}@{comp['version']}: {len(vulns)} vulnerabilities found")
        
        enriched.append(comp)
    
    return enriched