import json
import urllib.request
import urllib.error
import logging

logger = logging.getLogger()

# CISA KEV cache (loaded once per Lambda invocation)
_kev_cache = None


def get_epss_scores(cve_ids):
    """
    Query FIRST EPSS API for exploitation probability scores.
    
    Args:
        cve_ids: List of CVE IDs (e.g., ["CVE-2021-23337", "CVE-2022-23529"])
    
    Returns:
        Dict mapping CVE ID to EPSS score (0.0 to 1.0)
    """
    
    if not cve_ids:
        return {}
    
    # EPSS API accepts comma-separated CVE IDs
    cve_param = ",".join(cve_ids)
    url = f"https://api.first.org/data/v1/epss?cve={cve_param}"
    
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode('utf-8'))
        
        scores = {}
        for item in data.get('data', []):
            cve_id = item.get('cve')
            epss = item.get('epss')
            if cve_id and epss:
                scores[cve_id] = float(epss)
        
        return scores
        
    except urllib.error.URLError as e:
        logger.error(f"EPSS API error: {str(e)}")
        return {}
    except Exception as e:
        logger.error(f"Unexpected error querying EPSS: {str(e)}")
        return {}


def load_kev_catalog():
    """
    Load CISA Known Exploited Vulnerabilities catalog.
    Cached for the duration of the Lambda invocation.
    
    Returns:
        Set of CVE IDs that are in the KEV catalog
    """
    
    global _kev_cache
    
    if _kev_cache is not None:
        return _kev_cache
    
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=15) as response:
            data = json.loads(response.read().decode('utf-8'))
        
        _kev_cache = set()
        for vuln in data.get('vulnerabilities', []):
            cve_id = vuln.get('cveID')
            if cve_id:
                _kev_cache.add(cve_id)
        
        logger.info(f"Loaded {len(_kev_cache)} CVEs from CISA KEV catalog")
        return _kev_cache
        
    except urllib.error.URLError as e:
        logger.error(f"KEV catalog load error: {str(e)}")
        _kev_cache = set()
        return _kev_cache
    except Exception as e:
        logger.error(f"Unexpected error loading KEV: {str(e)}")
        _kev_cache = set()
        return _kev_cache


def enrich_vulnerabilities(components):
    """
    Enrich component vulnerabilities with EPSS scores and KEV status.
    
    Args:
        components: List of components with vulnerabilities from OSV
    
    Returns:
        Components with EPSS and KEV data added to each vulnerability
    """
    
    # Collect all CVE IDs
    all_cve_ids = []
    for comp in components:
        for vuln in comp.get('vulnerabilities', []):
            cve_id = vuln.get('cve_id')
            if cve_id:
                all_cve_ids.append(cve_id)
    
    # Batch lookup EPSS scores
    epss_scores = get_epss_scores(all_cve_ids)
    logger.info(f"Retrieved EPSS scores for {len(epss_scores)} CVEs")
    
    # Load KEV catalog
    kev_set = load_kev_catalog()
    
    # Enrich each vulnerability
    for comp in components:
        for vuln in comp.get('vulnerabilities', []):
            cve_id = vuln.get('cve_id')
            
            if cve_id:
                vuln['epss'] = epss_scores.get(cve_id, 0.0)
                vuln['in_kev'] = cve_id in kev_set
            else:
                vuln['epss'] = 0.0
                vuln['in_kev'] = False
    
    return components