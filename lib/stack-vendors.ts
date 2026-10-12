// Vendors the SOC team runs. Their vulnerability news and CVEs are always shown above
// everything else.

export const STACK_VENDORS: Array<{ name: string; regex: RegExp }> = [
  { name: 'Citrix',    regex: /\bcitrix|netscaler|xenapp|xendesktop|sharefile/i },
  { name: 'Palo Alto', regex: /palo.?alto|\bpan-?os\b|globalprotect|\bpanorama\b|cortex.?(xdr|xsoar|xsiam)|prisma.?(cloud|access)/i },
  { name: 'Splunk',    regex: /\bsplunk/i },
  { name: 'VMray',     regex: /\bvmray/i },
  { name: 'Microsoft', regex: /\bmicrosoft|\bwindows\b|exchange.?server|exchange.?online|\bsharepoint|\bazure\b|\bentra\b|\bm365\b|office.?365|\boutlook\b|hyper-v|\biis\b|asp\.net|\.net.?(framework|core)|sql.?server|active.?directory|\bintune\b|\bkerberos\b|\bntlm\b|patch.?tuesday/i },
  { name: 'Cisco',     regex: /\bcisco|\bios.?x[er]\b|\basa\b|firepower|\bwebex|meraki|anyconnect|identity.?services.?engine|\bnx-?os\b/i },
  { name: 'Oracle',    regex: /\boracle|weblogic|peoplesoft|e-business.?suite|jd.?edwards|virtualbox/i },
];

// Passing mentions that don't make a story about the vendor
const IMPERSONATION = /\b(?:disguised as|posing as|masquerading as|impersonat\w*|fake|spoofed|lookalike)\s+(?:an?\s+|the\s+)?[\w.-]+(?:\s+[\w.-]+)?/gi;
const RESEARCH_ARM  = /\b(?:microsoft threat intelligence|microsoft security response center|cisco talos|talos|unit ?42)\b/gi;
const ATTRIBUTION   = /\b(?:microsoft|cisco|palo alto networks|oracle|citrix|splunk|vmray)(?:'s)?\s+(?:has\s+|have\s+)?(?:warned|warns|said|says|reported|reports|observed|spotted|discovered|found|detected|researchers?)\b/gi;
const VULN_STORY    = /cve-\d{4}-\d+|vulnerab|flaw|\bbugs?\b|exploit|zero.?days?|\b0.?days?\b|\brce\b|remote code|patch|security update|advisory|bypass|injection|overflow|privilege/i;

// Vendors a news story is about — matched on headline + lede only
export function storyVendors(title: string, description: string): string[] {
  const lede = description.slice(0, 200).replace(ATTRIBUTION, ' ');
  const text = `${title} ${lede}`.replace(IMPERSONATION, ' ').replace(RESEARCH_ARM, ' ');
  return STACK_VENDORS.filter(v => v.regex.test(text)).map(v => v.name);
}

// Stack-vendor vulnerability news (not every story that names the vendor)
export function isStackStory(title: string, description: string, cves: string[]): boolean {
  if (storyVendors(title, description).length === 0) return false;
  return cves.length > 0 || VULN_STORY.test(`${title} ${description.slice(0, 200)}`);
}

// Vendors a CVE affects — from NVD's vendor/product, or the start of the description when
// NVD has no product data yet ("... in Citrix NetScaler ADC ...")
export function cveVendors(vendor: string, product: string, description: string): string[] {
  const text = vendor || product ? `${vendor} ${product}` : description.slice(0, 160);
  return STACK_VENDORS.filter(v => v.regex.test(text)).map(v => v.name);
}
