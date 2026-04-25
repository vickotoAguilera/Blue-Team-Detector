/**
 * NVD API Utility
 * Provides functions to interact with the National Vulnerability Database API
 */

const NVD_API_BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const API_KEY = process.env.NVD_API_KEY;

export interface NVDVulnerability {
  cveId: string;
  description: string;
  severity: string;
  baseScore: number;
  vectorString: string;
  references: string[];
}

/**
 * Fetches CVE details from the NVD API
 * @param cveId The CVE ID (e.g., 'CVE-2024-23897')
 * @returns CVE details or null if not found
 */
export async function fetchCVEDetails(cveId: string): Promise<NVDVulnerability | null> {
  if (!API_KEY) {
    console.warn('NVD_API_KEY is not configured. Returning null.');
    return null;
  }

  try {
    const response = await fetch(`${NVD_API_BASE_URL}?cveId=${cveId}`, {
      headers: {
        'apiKey': API_KEY,
      },
    });

    if (!response.ok) {
      throw new Error(`NVD API responded with status: ${response.status}`);
    }

    const data = await response.json();
    const vulnerability = data.vulnerabilities?.[0]?.cve;

    if (!vulnerability) {
      return null;
    }

    const description = vulnerability.descriptions.find((d: any) => d.lang === 'en')?.value || 'No description available.';
    const metrics = vulnerability.metrics?.cvssMetricV31?.[0] || vulnerability.metrics?.cvssMetricV30?.[0] || vulnerability.metrics?.cvssMetricV2?.[0];
    
    const severity = metrics?.cvssData?.baseSeverity || 'UNKNOWN';
    const baseScore = metrics?.cvssData?.baseScore || 0;
    const vectorString = metrics?.cvssData?.vectorString || 'N/A';
    const references = vulnerability.references.map((r: any) => r.url);

    return {
      cveId,
      description,
      severity,
      baseScore,
      vectorString,
      references,
    };
  } catch (error) {
    console.error(`Error fetching CVE details for ${cveId}:`, error);
    return null;
  }
}
