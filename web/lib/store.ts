import { threatRepo, clientRepo } from './db';
export { getVaultStats } from './db';

// Clean hostname helper
export function cleanHostname(domainOrUrl: string): string {
    try {
        let hostname = domainOrUrl.trim().toLowerCase();
        if (hostname.includes('://')) {
            hostname = new URL(hostname).hostname;
        } else if (hostname.includes('/')) {
            hostname = hostname.split('/')[0];
        }
        if (hostname.startsWith('www.')) {
            hostname = hostname.slice(4);
        }
        if (hostname.includes(':')) {
            hostname = hostname.split(':')[0];
        }
        return hostname;
    } catch {
        return domainOrUrl.toLowerCase().trim().replace(/^www\./, '');
    }
}

// Compatibility wrapper object providing Map-like methods backed by SQLite
export const threatRegistry = {
    get: (hash: string) => threatRepo.get(hash),
    set: (hash: string, record: any) => threatRepo.save(record),
    has: (hash: string) => Boolean(threatRepo.get(hash)),
    values: () => threatRepo.getAll(),
    size: () => threatRepo.getStats().totalThreats
};

export const syncLogs = {
    size: () => threatRepo.getStats().totalSyncs
};
