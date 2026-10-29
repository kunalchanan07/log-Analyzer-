import * as d3 from 'd3';

export interface GeoLocation {
  ip: string;
  country: string;
  countryCode: string;
  city: string;
  lat: number;
  lng: number;
  asn?: string;
  org?: string;
}

// Well-known threat IPs mapped to precise real-world threat actor infrastructure locations
export const KNOWN_IP_GEO_DB: Record<string, Omit<GeoLocation, 'ip'>> = {
  '185.220.101.5': {
    country: 'Netherlands',
    countryCode: 'NL',
    city: 'Amsterdam',
    lat: 52.3676,
    lng: 4.9041,
    asn: 'AS208323',
    org: 'Tor Exit Relay Network'
  },
  '45.145.185.10': {
    country: 'Russia',
    countryCode: 'RU',
    city: 'Moscow',
    lat: 55.7558,
    lng: 37.6173,
    asn: 'AS57523',
    org: 'Bulletproof Botnet Hosting'
  },
  '194.26.29.112': {
    country: 'Germany',
    countryCode: 'DE',
    city: 'Frankfurt',
    lat: 50.1109,
    lng: 8.6821,
    asn: 'AS44592',
    org: 'Automated Port Scanner Net'
  },
  '103.149.28.18': {
    country: 'China',
    countryCode: 'CN',
    city: 'Beijing',
    lat: 39.9042,
    lng: 116.4074,
    asn: 'AS4134',
    org: 'Scanning Network Infrastructure'
  },
  '91.240.118.232': {
    country: 'Ukraine',
    countryCode: 'UA',
    city: 'Kyiv',
    lat: 50.4501,
    lng: 30.5234,
    asn: 'AS200000',
    org: 'Cobalt Strike C2 Node'
  },
  '198.51.100.44': {
    country: 'United States',
    countryCode: 'US',
    city: 'Ashburn, VA',
    lat: 39.0438,
    lng: -77.4874,
    asn: 'AS14618',
    org: 'Public Cloud Exploit Probe'
  },
  '10.0.4.15': {
    country: 'United States',
    countryCode: 'US',
    city: 'San Francisco, CA',
    lat: 37.7749,
    lng: -122.4194,
    asn: 'Internal Subnet (Compromised)',
    org: 'Corporate Gateway Perimeter'
  }
};

// Global reference centers for deterministic fallback mapping
const GLOBAL_HUBS: Omit<GeoLocation, 'ip'>[] = [
  { country: 'United States', countryCode: 'US', city: 'New York', lat: 40.7128, lng: -74.006, org: 'US East Ingress' },
  { country: 'United Kingdom', countryCode: 'GB', city: 'London', lat: 51.5074, lng: -0.1278, org: 'EU West Gateway' },
  { country: 'Singapore', countryCode: 'SG', city: 'Singapore', lat: 1.3521, lng: 103.8198, org: 'APAC Transit Node' },
  { country: 'Japan', countryCode: 'JP', city: 'Tokyo', lat: 35.6762, lng: 139.6503, org: 'East Asia Probe' },
  { country: 'Brazil', countryCode: 'BR', city: 'São Paulo', lat: -23.5505, lng: -46.6333, org: 'South America Node' },
  { country: 'Australia', countryCode: 'AU', city: 'Sydney', lat: -33.8688, lng: 151.2093, org: 'Oceania Egress' },
  { country: 'India', countryCode: 'IN', city: 'Mumbai', lat: 19.076, lng: 72.8777, org: 'South Asia Gateway' },
  { country: 'Canada', countryCode: 'CA', city: 'Toronto', lat: 43.6532, lng: -79.3832, org: 'North America North' },
  { country: 'France', countryCode: 'FR', city: 'Paris', lat: 48.8566, lng: 2.3522, org: 'EU Central Core' },
  { country: 'South Africa', countryCode: 'ZA', city: 'Johannesburg', lat: -26.2041, lng: 28.0473, org: 'Africa South Hub' },
  { country: 'Romania', countryCode: 'RO', city: 'Bucharest', lat: 44.4268, lng: 26.1025, org: 'Eastern Europe Relay' },
  { country: 'South Korea', countryCode: 'KR', city: 'Seoul', lat: 37.5665, lng: 126.978, org: 'Seoul Cyber Gateway' }
];

export function getIpGeoLocation(ip: string): GeoLocation {
  if (KNOWN_IP_GEO_DB[ip]) {
    return { ip, ...KNOWN_IP_GEO_DB[ip] };
  }

  let hash = 0;
  for (let i = 0; i < ip.length; i++) {
    hash = (hash << 5) - hash + ip.charCodeAt(i);
    hash |= 0;
  }
  const positiveHash = Math.abs(hash);
  const hub = GLOBAL_HUBS[positiveHash % GLOBAL_HUBS.length];

  const lastOctet = parseInt(ip.split('.')[3] || '0', 10);
  const offsetLat = ((lastOctet % 20) - 10) * 0.15;
  const offsetLng = (((lastOctet * 3) % 20) - 10) * 0.15;

  return {
    ip,
    country: hub.country,
    countryCode: hub.countryCode,
    city: hub.city,
    lat: Math.max(-55, Math.min(70, hub.lat + offsetLat)),
    lng: Math.max(-175, Math.min(175, hub.lng + offsetLng)),
    org: hub.org
  };
}

export const PROTECTED_TARGET_DC = {
  name: 'Enterprise Primary DC (Frankfurt)',
  lat: 50.1109,
  lng: 8.6821
};

/**
 * Rich, cleanly outlined GeoJSON world continents and landmasses
 * All polygons wound in spherical counterclockwise order (area < 2*PI).
 */
export const WORLD_GEOJSON: GeoJSON.FeatureCollection = {
  type: 'FeatureCollection',
  features: [
    // North America (US, Canada, Mexico, Alaska)
    {
      type: 'Feature',
      properties: { name: 'North America', id: 'NA' },
      geometry: {
        type: 'Polygon',
        coordinates: [
          [
            [-168, 65], [-162, 70], [-145, 69], [-135, 69], [-120, 68],
            [-100, 70], [-90, 60], [-80, 62], [-70, 58], [-60, 50],
            [-65, 44], [-70, 42], [-76, 35], [-81, 25], [-80, 25],
            [-82, 30], [-89, 30], [-97, 26], [-97, 20], [-91, 19],
            [-88, 16], [-83, 9], [-77, 8], [-80, 14], [-86, 15],
            [-93, 16], [-105, 20], [-110, 23], [-115, 30], [-120, 34],
            [-124, 40], [-124, 48], [-130, 54], [-140, 60], [-150, 59],
            [-160, 55], [-168, 65]
          ]
        ]
      }
    },
    // Greenland
    {
      type: 'Feature',
      properties: { name: 'Greenland', id: 'GL' },
      geometry: {
        type: 'Polygon',
        coordinates: [
          [
            [-45, 60], [-55, 62], [-52, 70], [-58, 76], [-40, 83],
            [-25, 82], [-18, 77], [-22, 70], [-35, 65], [-45, 60]
          ]
        ]
      }
    },
    // South America
    {
      type: 'Feature',
      properties: { name: 'South America', id: 'SA' },
      geometry: {
        type: 'Polygon',
        coordinates: [
          [
            [-77, 8], [-72, 12], [-62, 10], [-52, 5], [-44, -2],
            [-35, -5], [-35, -9], [-39, -15], [-40, -22], [-48, -28],
            [-53, -33], [-58, -38], [-65, -43], [-66, -54], [-73, -53],
            [-75, -45], [-73, -35], [-71, -25], [-76, -15], [-81, -5],
            [-79, 1], [-77, 8]
          ]
        ]
      }
    },
    // Europe
    {
      type: 'Feature',
      properties: { name: 'Europe', id: 'EU' },
      geometry: {
        type: 'Polygon',
        coordinates: [
          [
            [-9, 37], [-9, 43], [-2, 43], [-1, 46], [-4, 48],
            [1, 50], [5, 52], [8, 55], [10, 54], [14, 54],
            [19, 54], [25, 56], [28, 60], [30, 65], [40, 66],
            [50, 60], [55, 55], [48, 50], [42, 47], [35, 47],
            [30, 46], [28, 41], [23, 38], [20, 39], [15, 38],
            [12, 43], [9, 44], [3, 42], [-3, 37], [-9, 37]
          ]
        ]
      }
    },
    // British Isles (Corrected winding)
    {
      type: 'Feature',
      properties: { name: 'United Kingdom & Ireland', id: 'UK' },
      geometry: {
        type: 'Polygon',
        coordinates: [
          [
            [-10, 51], [-10, 53], [-8, 55], [-6, 56], [-4, 59],
            [-1, 58], [0, 54], [1, 52], [-1, 51], [-6, 50], [-10, 51]
          ]
        ]
      }
    },
    // Scandinavia (Corrected winding)
    {
      type: 'Feature',
      properties: { name: 'Scandinavia', id: 'SCAN' },
      geometry: {
        type: 'Polygon',
        coordinates: [
          [
            [5, 59], [6, 62], [13, 65], [18, 69], [24, 71],
            [28, 70], [24, 65], [19, 60], [16, 56], [12, 56],
            [10, 58], [5, 59]
          ]
        ]
      }
    },
    // Africa
    {
      type: 'Feature',
      properties: { name: 'Africa', id: 'AF' },
      geometry: {
        type: 'Polygon',
        coordinates: [
          [
            [-6, 36], [10, 37], [20, 33], [30, 31], [33, 28],
            [37, 23], [43, 12], [51, 11], [45, 5], [41, -2],
            [39, -10], [35, -20], [32, -28], [28, -34], [18, -34],
            [12, -22], [10, -5], [5, 4], [-2, 5], [-8, 5],
            [-14, 11], [-17, 15], [-17, 21], [-12, 28], [-6, 36]
          ]
        ]
      }
    },
    // Madagascar
    {
      type: 'Feature',
      properties: { name: 'Madagascar', id: 'MD' },
      geometry: {
        type: 'Polygon',
        coordinates: [
          [
            [44, -13], [50, -13], [50, -22], [47, -26], [44, -22], [44, -13]
          ]
        ]
      }
    },
    // Asia (Eurasia Continental)
    {
      type: 'Feature',
      properties: { name: 'Asia', id: 'AS' },
      geometry: {
        type: 'Polygon',
        coordinates: [
          [
            [40, 45], [50, 48], [60, 55], [70, 65], [85, 72],
            [105, 75], [130, 72], [150, 70], [170, 66], [180, 65],
            [170, 60], [158, 53], [142, 50], [135, 43], [130, 38],
            [122, 35], [121, 31], [118, 22], [108, 19], [105, 10],
            [103, 1], [98, 10], [92, 16], [88, 22], [81, 17],
            [78, 8], [75, 15], [69, 23], [60, 25], [52, 27],
            [47, 30], [36, 32], [36, 37], [40, 45]
          ]
        ]
      }
    },
    // Arabian Peninsula
    {
      type: 'Feature',
      properties: { name: 'Arabian Peninsula', id: 'ARAB' },
      geometry: {
        type: 'Polygon',
        coordinates: [
          [
            [35, 30], [40, 30], [48, 30], [52, 25], [60, 23],
            [55, 17], [45, 13], [43, 14], [38, 23], [35, 30]
          ]
        ]
      }
    },
    // Japan (Corrected winding)
    {
      type: 'Feature',
      properties: { name: 'Japan', id: 'JP' },
      geometry: {
        type: 'Polygon',
        coordinates: [
          [
            [130, 31], [130, 33], [135, 36], [139, 41], [142, 45],
            [145, 44], [141, 39], [138, 35], [133, 34], [130, 31]
          ]
        ]
      }
    },
    // Australia
    {
      type: 'Feature',
      properties: { name: 'Australia', id: 'AU' },
      geometry: {
        type: 'Polygon',
        coordinates: [
          [
            [114, -22], [122, -18], [130, -13], [136, -12], [142, -11],
            [146, -18], [153, -28], [150, -37], [140, -38], [136, -34],
            [125, -34], [115, -34], [113, -26], [114, -22]
          ]
        ]
      }
    },
    // Maritime Southeast Asia (Corrected winding)
    {
      type: 'Feature',
      properties: { name: 'Maritime SE Asia', id: 'MSEA' },
      geometry: {
        type: 'Polygon',
        coordinates: [
          [
            [95, 5], [100, 2], [110, 4], [122, 2], [132, -3],
            [125, -8], [115, -8], [104, -5], [95, 5]
          ]
        ]
      }
    },
    // New Zealand (Corrected winding)
    {
      type: 'Feature',
      properties: { name: 'New Zealand', id: 'NZ' },
      geometry: {
        type: 'Polygon',
        coordinates: [
          [
            [167, -46], [168, -44], [172, -39], [175, -35], [178, -38],
            [175, -41], [171, -43], [167, -46]
          ]
        ]
      }
    }
  ]
};

// Guarantee all feature polygons are properly wound (area < 2*PI)
WORLD_GEOJSON.features.forEach((feature) => {
  if (feature.geometry.type === 'Polygon') {
    const area = d3.geoArea(feature as any);
    if (area > 2 * Math.PI) {
      (feature.geometry as any).coordinates[0].reverse();
    }
  }
});
