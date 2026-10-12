export interface Coverage { source: string; title: string; link: string; pubDate: string; }

// A news story: its best article, plus other outlets' coverage of the same story
export interface Story {
  id: string;
  title: string;
  link: string;
  source: string;
  description: string;
  pubDate: string;   // newest coverage
  firstSeen: string; // first coverage
  tags: string[];
  cves: string[];
  cveStatus?: string; // article page checked for CVE IDs: pending | found | none | unavailable
  coverage: Coverage[];
}

export interface NewsData { stories: Story[]; updatedAt: string | null; refreshing: boolean; }

export interface CveItem {
  id: string;
  published: string;
  description: string;
  score: number | null;
  severity: string | null;
  cvssVersion: string | null;
  vector: string | null;
  vendor: string;
  product: string;
  cwe: string;
  wordpress: boolean;
  refs: string[];
}

export interface KevItem {
  id: string;
  vendor: string;
  product: string;
  name: string;
  description: string;
  dateAdded: string;
  dueDate: string;
  ransomware: boolean;
}

export interface CveData {
  cves: CveItem[];
  kevRecent: KevItem[];
  kevIds: string[];
  nvdSyncedAt: string | null;
  kevSyncedAt: string | null;
  refreshing: boolean;
}

// What the news tab knows about a CVE (score from NVD, KEV status)
export interface CveInfo { score: number | null; severity: string | null; kev: boolean; }
