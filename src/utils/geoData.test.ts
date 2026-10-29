import test from 'node:test';
import assert from 'node:assert/strict';
import * as d3 from 'd3';
import { getIpGeoLocation, KNOWN_IP_GEO_DB, WORLD_GEOJSON } from './geoData';

test('getIpGeoLocation correctly resolves known threat IPs', () => {
  const torIp = '185.220.101.5';
  const geo1 = getIpGeoLocation(torIp);
  assert.equal(geo1.country, 'Netherlands');
  assert.equal(geo1.city, 'Amsterdam');
  assert.equal(geo1.lat, 52.3676);
  assert.equal(geo1.lng, 4.9041);

  const russiaIp = '45.145.185.10';
  const geo2 = getIpGeoLocation(russiaIp);
  assert.equal(geo2.country, 'Russia');
  assert.equal(geo2.city, 'Moscow');

  const beijingIp = '103.149.28.18';
  const geo3 = getIpGeoLocation(beijingIp);
  assert.equal(geo3.country, 'China');
  assert.equal(geo3.city, 'Beijing');
});

test('getIpGeoLocation deterministically resolves arbitrary dynamic IPs', () => {
  const ip = '198.51.100.99';
  const geoA = getIpGeoLocation(ip);
  const geoB = getIpGeoLocation(ip);

  assert.equal(geoA.country, geoB.country);
  assert.equal(geoA.lat, geoB.lat);
  assert.equal(geoA.lng, geoB.lng);
  assert.ok(geoA.lat >= -90 && geoA.lat <= 90);
  assert.ok(geoA.lng >= -180 && geoA.lng <= 180);
});

test('WORLD_GEOJSON polygons all have valid non-inverted spherical areas (< 2*PI)', () => {
  for (const feature of WORLD_GEOJSON.features) {
    const area = d3.geoArea(feature as any);
    assert.ok(
      area < 2 * Math.PI,
      `Feature ${feature.properties?.name} has inverted area: ${area}`
    );
    assert.ok(
      area > 0,
      `Feature ${feature.properties?.name} has invalid zero area`
    );
  }
});
