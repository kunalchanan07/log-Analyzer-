import React, { useEffect, useRef, useState, useMemo } from 'react';
import * as d3 from 'd3';
import { 
  Globe2, 
  ZoomIn, 
  ZoomOut, 
  RotateCcw, 
  ShieldX, 
  Crosshair, 
  ExternalLink,
  Activity,
  Layers,
  MapPin
} from 'lucide-react';
import { LogEntry, Severity } from '../types/soc';
import { 
  getIpGeoLocation, 
  WORLD_GEOJSON, 
  PROTECTED_TARGET_DC, 
  GeoLocation 
} from '../utils/geoData';
import { Language } from '../utils/i18n';

interface ThreatOriginMapProps {
  logs: LogEntry[];
  lang: Language;
  onSelectLog?: (log: LogEntry) => void;
  onBlockIp: (ip: string) => void;
  blockedIps: Set<string>;
}

export interface ThreatNode {
  ip: string;
  geo: GeoLocation;
  count: number;
  maxSeverity: Severity;
  categories: string[];
  latestLog: LogEntry;
  isBlocked: boolean;
}

export const ThreatOriginMap: React.FC<ThreatOriginMapProps> = ({
  logs,
  lang,
  onSelectLog,
  onBlockIp,
  blockedIps
}) => {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const gRef = useRef<d3.Selection<SVGGElement, unknown, null, undefined> | null>(null);
  const zoomBehaviorRef = useRef<d3.ZoomBehavior<SVGSVGElement, unknown> | null>(null);

  const [hoveredNode, setHoveredNode] = useState<ThreatNode | null>(null);
  const [selectedNode, setSelectedNode] = useState<ThreatNode | null>(null);
  const [severityFilter, setSeverityFilter] = useState<Severity | 'all'>('all');
  const [showArcs, setShowArcs] = useState(true);
  const [tooltipPos, setTooltipPos] = useState<{ x: number; y: number } | null>(null);

  // Projection setup: Natural Earth centered to showcase full global span
  const projection = useMemo(() => {
    return d3.geoNaturalEarth1()
      .scale(152)
      .translate([480, 240]);
  }, []);

  // Aggregate attacker IPs found in current logs
  const threatNodes = useMemo(() => {
    const nodeMap = new Map<string, ThreatNode>();
    const relevantLogs = logs.filter(l => l.isMalicious || l.isSuspicious);

    for (const log of relevantLogs) {
      const ip = log.sourceIp;
      if (!ip) continue;

      const existing = nodeMap.get(ip);
      if (existing) {
        existing.count += 1;
        if (!existing.categories.includes(log.category)) {
          existing.categories.push(log.category);
        }
        if (
          log.severity === 'critical' ||
          (log.severity === 'high' && existing.maxSeverity !== 'critical') ||
          (log.severity === 'medium' && existing.maxSeverity === 'low')
        ) {
          existing.maxSeverity = log.severity;
        }
        if (new Date(log.timestamp) > new Date(existing.latestLog.timestamp)) {
          existing.latestLog = log;
        }
      } else {
        const geo = getIpGeoLocation(ip);
        nodeMap.set(ip, {
          ip,
          geo,
          count: 1,
          maxSeverity: log.severity,
          categories: [log.category],
          latestLog: log,
          isBlocked: blockedIps.has(ip)
        });
      }
    }

    return Array.from(nodeMap.values()).map(node => ({
      ...node,
      isBlocked: blockedIps.has(node.ip)
    }));
  }, [logs, blockedIps]);

  // Filtered nodes
  const filteredNodes = useMemo(() => {
    if (severityFilter === 'all') return threatNodes;
    return threatNodes.filter(n => n.maxSeverity === severityFilter);
  }, [threatNodes, severityFilter]);

  // Origin countries list
  const originCountries = useMemo(() => {
    const set = new Set<string>();
    threatNodes.forEach(n => set.add(n.geo.country));
    return Array.from(set);
  }, [threatNodes]);

  // 1. One-time Setup of Base Map Geometry and Zoom
  useEffect(() => {
    if (!svgRef.current) return;

    const width = 960;
    const height = 480;
    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    const pathGenerator = d3.geoPath().projection(projection);

    // Root Group
    const g = svg.append('g').attr('class', 'map-root');
    gRef.current = g;

    // Zoom behavior
    const zoom = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([1, 8])
      .translateExtent([[0, 0], [width, height]])
      .on('zoom', (event) => {
        g.attr('transform', event.transform);
      });

    zoomBehaviorRef.current = zoom;
    svg.call(zoom);

    // Ocean Sphere Background
    g.append('path')
      .datum({ type: 'Sphere' } as any)
      .attr('class', 'sphere-bg')
      .attr('d', pathGenerator as any)
      .attr('fill', '#070c18')
      .attr('stroke', '#1e293b')
      .attr('stroke-width', 1);

    // Graticules
    const graticule = d3.geoGraticule10();
    g.append('path')
      .datum(graticule)
      .attr('class', 'graticule')
      .attr('d', pathGenerator)
      .attr('fill', 'none')
      .attr('stroke', '#1e293b')
      .attr('stroke-width', 0.5)
      .attr('opacity', 0.5);

    // Landmass Polygons (Clear visible cyber continents)
    g.append('g')
      .attr('class', 'countries-layer')
      .selectAll('path')
      .data(WORLD_GEOJSON.features)
      .enter()
      .append('path')
      .attr('d', pathGenerator as any)
      .attr('fill', '#1e293b')
      .attr('stroke', '#334155')
      .attr('stroke-width', 1)
      .attr('opacity', 0.95);

    // Protected Datacenter Target Marker (Frankfurt)
    const targetCoords = projection([PROTECTED_TARGET_DC.lng, PROTECTED_TARGET_DC.lat]);
    if (targetCoords) {
      const [tx, ty] = targetCoords;

      const dcG = g.append('g')
        .attr('class', 'target-dc')
        .style('pointer-events', 'none');

      dcG.append('circle')
        .attr('cx', tx)
        .attr('cy', ty)
        .attr('r', 12)
        .attr('fill', 'none')
        .attr('stroke', '#06b6d4')
        .attr('stroke-width', 1.5)
        .attr('opacity', 0.4);

      dcG.append('circle')
        .attr('cx', tx)
        .attr('cy', ty)
        .attr('r', 4.5)
        .attr('fill', '#06b6d4')
        .attr('stroke', '#ffffff')
        .attr('stroke-width', 1.5);

      dcG.append('text')
        .attr('x', tx + 8)
        .attr('y', ty - 8)
        .attr('font-size', '9px')
        .attr('font-family', 'JetBrains Mono, monospace')
        .attr('font-weight', 'bold')
        .attr('fill', '#22d3ee')
        .text('PRIMARY DC (TARGET)');
    }

    // Dynamic layers placeholders
    g.append('g').attr('class', 'arcs-layer');
    g.append('g').attr('class', 'nodes-layer');

  }, [projection]);

  // 2. Dynamic Update of Trajectory Arcs and Threat Nodes
  useEffect(() => {
    if (!gRef.current) return;

    const g = gRef.current;
    const arcsLayer = g.select('.arcs-layer');
    const nodesLayer = g.select('.nodes-layer');

    arcsLayer.selectAll('*').remove();
    nodesLayer.selectAll('*').remove();

    const targetCoords = projection([PROTECTED_TARGET_DC.lng, PROTECTED_TARGET_DC.lat]);

    // Draw Attack Trajectory Arcs
    if (showArcs && targetCoords) {
      const [tx, ty] = targetCoords;

      filteredNodes.forEach((node) => {
        const sourceCoords = projection([node.geo.lng, node.geo.lat]);
        if (!sourceCoords) return;

        const [sx, sy] = sourceCoords;
        const dx = tx - sx;
        const dy = ty - sy;
        const dist = Math.sqrt(dx * dx + dy * dy);

        // Curvature calculation
        const cx = (sx + tx) / 2 - dy * 0.22;
        const cy = (sy + ty) / 2 + dx * 0.22 - dist * 0.12;

        const pathData = `M ${sx} ${sy} Q ${cx} ${cy} ${tx} ${ty}`;

        const strokeColor =
          node.maxSeverity === 'critical'
            ? '#f43f5e'
            : node.maxSeverity === 'high'
            ? '#f59e0b'
            : '#38bdf8';

        // Static dashed guide line
        arcsLayer.append('path')
          .attr('d', pathData)
          .attr('fill', 'none')
          .attr('stroke', strokeColor)
          .attr('stroke-width', Math.min(2.5, 0.8 + node.count * 0.3))
          .attr('stroke-opacity', 0.35)
          .attr('stroke-dasharray', '4,4');

        // Animated flow pulse
        arcsLayer.append('path')
          .attr('d', pathData)
          .attr('fill', 'none')
          .attr('stroke', strokeColor)
          .attr('stroke-width', Math.min(2.5, 1.2 + node.count * 0.3))
          .attr('stroke-opacity', 0.85)
          .attr('stroke-dasharray', '6,18')
          .append('animate')
          .attr('attributeName', 'stroke-dashoffset')
          .attr('from', '48')
          .attr('to', '0')
          .attr('dur', '1.6s')
          .attr('repeatCount', 'indefinite');
      });
    }

    // Draw Attacker IP Nodes
    const maxCount = d3.max(threatNodes, d => d.count) || 1;
    const radiusScale = d3.scaleSqrt()
      .domain([1, Math.max(5, maxCount)])
      .range([5, 13]);

    filteredNodes.forEach((node) => {
      const coords = projection([node.geo.lng, node.geo.lat]);
      if (!coords) return;

      const [nx, ny] = coords;
      const radius = radiusScale(node.count);

      const color =
        node.maxSeverity === 'critical'
          ? '#f43f5e'
          : node.maxSeverity === 'high'
          ? '#f59e0b'
          : '#38bdf8';

      const nodeG = nodesLayer.append('g')
        .attr('class', 'node-item cursor-pointer')
        .attr('data-ip', node.ip)
        .attr('tabindex', '0')
        .attr('role', 'button')
        .attr('aria-label', `Threat node ${node.ip} in ${node.geo.city}, ${node.geo.country}`)
        .on('mouseenter', (event) => {
          setHoveredNode(node);
          const rect = containerRef.current?.getBoundingClientRect();
          if (rect) {
            setTooltipPos({
              x: event.clientX - rect.left,
              y: event.clientY - rect.top
            });
          }
        })
        .on('mousemove', (event) => {
          const rect = containerRef.current?.getBoundingClientRect();
          if (rect) {
            setTooltipPos({
              x: event.clientX - rect.left,
              y: event.clientY - rect.top
            });
          }
        })
        .on('mouseleave', () => {
          setHoveredNode(null);
        })
        .on('click', (event) => {
          event.stopPropagation();
          setSelectedNode(node);
        });

      // Outer animated pulsing beacon for Critical / High threats
      if (node.maxSeverity === 'critical' || node.maxSeverity === 'high') {
        const pulse = nodeG.append('circle')
          .attr('cx', nx)
          .attr('cy', ny)
          .attr('r', radius * 1.8)
          .attr('fill', 'none')
          .attr('stroke', color)
          .attr('stroke-width', 1.5)
          .attr('opacity', 0.6)
          .style('pointer-events', 'none');

        pulse.append('animate')
          .attr('attributeName', 'r')
          .attr('from', radius)
          .attr('to', radius * 2.3)
          .attr('dur', '1.8s')
          .attr('repeatCount', 'indefinite');

        pulse.append('animate')
          .attr('attributeName', 'opacity')
          .attr('from', '0.7')
          .attr('to', '0')
          .attr('dur', '1.8s')
          .attr('repeatCount', 'indefinite');
      }

      // Base Target Clickable Circle
      nodeG.append('circle')
        .attr('cx', nx)
        .attr('cy', ny)
        .attr('r', radius)
        .attr('fill', color)
        .attr('fill-opacity', 0.9)
        .attr('stroke', node.isBlocked ? '#ef4444' : '#ffffff')
        .attr('stroke-width', node.isBlocked ? 2 : 1.2);

      // Inner dot (non-intercepting)
      nodeG.append('circle')
        .attr('cx', nx)
        .attr('cy', ny)
        .attr('r', 2)
        .attr('fill', '#ffffff')
        .style('pointer-events', 'none');

      // IP Label for high volume or critical nodes
      if (node.count >= 2 || node.maxSeverity === 'critical') {
        nodeG.append('text')
          .attr('x', nx + radius + 4)
          .attr('y', ny + 3)
          .attr('font-size', '8.5px')
          .attr('font-family', 'JetBrains Mono, monospace')
          .attr('font-weight', '600')
          .attr('fill', '#f1f5f9')
          .style('pointer-events', 'none')
          .text(`${node.ip}`);
      }
    });

  }, [filteredNodes, threatNodes, showArcs, projection]);

  // Zoom controls
  const handleZoom = (factor: number) => {
    if (!svgRef.current || !zoomBehaviorRef.current) return;
    d3.select(svgRef.current)
      .transition()
      .duration(300)
      .call(zoomBehaviorRef.current.scaleBy as any, factor);
  };

  const handleResetZoom = () => {
    if (!svgRef.current || !zoomBehaviorRef.current) return;
    d3.select(svgRef.current)
      .transition()
      .duration(400)
      .call(zoomBehaviorRef.current.transform as any, d3.zoomIdentity);
  };

  return (
    <div className="space-y-4">
      {/* Visual Component Header & Controls */}
      <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Globe2 className="w-5 h-5 text-cyan-400" />
            <h2 className="text-sm font-bold text-white tracking-tight">
              {lang === 'pa' ? 'ਗਲੋਬਲ ਖਤਰਾ ਉਤਪਤੀ ਨਕਸ਼ਾ (D3.js)' : 'Global Threat Origins & Trajectory Map'}
            </h2>
            <span className="text-[10px] font-mono text-cyan-400 border border-cyan-500/30 px-1.5 py-0.2 rounded bg-cyan-950/40">
              D3 Geo
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            {lang === 'pa'
              ? 'ਮੌਜੂਦਾ ਲੌਗ ਡੇਟਾ ਵਿੱਚੋਂ ਹਮਲਾਵਰ IPs ਦੀ ਭੂਗੋਲਿਕ ਸਥਿਤੀ ਅਤੇ ਡਾਟਾਸੈਂਟਰ ਵੱਲ ਅਟੈਕ ਫਲੋਅ'
              : 'Real-time geographic geolocation of attacker IPs plotted with attack trajectory vectors toward protected datacenter'}
          </p>
        </div>

        {/* Filter & Arc Controls */}
        <div className="flex items-center gap-2 flex-wrap">
          {/* Severity selector */}
          <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs">
            {(['all', 'critical', 'high', 'medium'] as const).map(sev => (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={`px-2 py-1 rounded text-[11px] font-medium capitalize transition-colors ${
                  severityFilter === sev
                    ? 'bg-slate-800 text-white font-semibold shadow-xs'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>

          {/* Arcs toggle */}
          <button
            onClick={() => setShowArcs(!showArcs)}
            className={`px-2.5 py-1.5 rounded-lg border text-xs font-medium flex items-center gap-1.5 transition-colors ${
              showArcs
                ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40'
                : 'bg-slate-950 text-slate-400 border-slate-800'
            }`}
            title="Toggle Attack Flow Vectors"
          >
            <Activity className="w-3.5 h-3.5" />
            <span>{lang === 'pa' ? 'ਵੈਕਟਰ ਲਾਈਨਾਂ' : 'Attack Vectors'}</span>
          </button>
        </div>
      </div>

      {/* Map Stats Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
        <div className="p-3 rounded-lg bg-slate-950 border border-slate-800/90">
          <div className="text-[11px] text-slate-500 font-sans">
            {lang === 'pa' ? 'ਪਛਾਣ ਕੀਤੇ ਹਮਲਾਵਰ IPs' : 'Plotted Attacker IPs'}
          </div>
          <div className="mt-1 text-lg font-bold text-white tabular-nums">
            {threatNodes.length}
          </div>
        </div>

        <div className="p-3 rounded-lg bg-slate-950 border border-slate-800/90">
          <div className="text-[11px] text-slate-500 font-sans">
            {lang === 'pa' ? 'ਉਤਪਤੀ ਦੇਸ਼ (Countries)' : 'Threat Origin Countries'}
          </div>
          <div className="mt-1 text-lg font-bold text-cyan-400 tabular-nums truncate">
            {originCountries.length} <span className="text-xs text-slate-400 font-sans font-normal">({originCountries.slice(0, 2).join(', ')})</span>
          </div>
        </div>

        <div className="p-3 rounded-lg bg-slate-950 border border-slate-800/90">
          <div className="text-[11px] text-slate-500 font-sans">
            {lang === 'pa' ? 'ਕੁੱਲ ਮਲੀਸ਼ੀਅਸ ਘਟਨਾਵਾਂ' : 'Attacks in Trajectory'}
          </div>
          <div className="mt-1 text-lg font-bold text-rose-400 tabular-nums">
            {threatNodes.reduce((acc, curr) => acc + curr.count, 0)}
          </div>
        </div>

        <div className="p-3 rounded-lg bg-slate-950 border border-slate-800/90">
          <div className="text-[11px] text-slate-500 font-sans">
            {lang === 'pa' ? 'ਸਰਹੱਦ ਤੇ ਬਲਾਕਡ IPs' : 'Perimeter Blocked'}
          </div>
          <div className="mt-1 text-lg font-bold text-emerald-400 tabular-nums">
            {threatNodes.filter(n => n.isBlocked).length}
          </div>
        </div>
      </div>

      {/* D3 World Map Canvas Container */}
      <div 
        ref={containerRef}
        className="relative rounded-xl bg-slate-950 border border-slate-800 overflow-hidden shadow-2xl"
        style={{ minHeight: '440px' }}
      >
        {/* SVG Surface */}
        <svg
          ref={svgRef}
          viewBox="0 0 960 480"
          className="w-full h-auto block select-none bg-slate-950"
        />

        {/* Zoom Controls overlay */}
        <div className="absolute top-4 right-4 flex flex-col gap-1.5 bg-slate-900/90 border border-slate-800 p-1.5 rounded-lg shadow-lg backdrop-blur-xs">
          <button
            onClick={() => handleZoom(1.4)}
            className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-800 rounded transition-colors"
            title="Zoom In"
            aria-label="Zoom in on map"
          >
            <ZoomIn className="w-4 h-4" />
          </button>
          <button
            onClick={() => handleZoom(0.7)}
            className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-800 rounded transition-colors"
            title="Zoom Out"
            aria-label="Zoom out on map"
          >
            <ZoomOut className="w-4 h-4" />
          </button>
          <button
            onClick={handleResetZoom}
            className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-800 rounded transition-colors"
            title="Reset Zoom"
            aria-label="Reset map view"
          >
            <RotateCcw className="w-4 h-4" />
          </button>
        </div>

        {/* Legend */}
        <div className="absolute bottom-4 left-4 bg-slate-900/90 border border-slate-800 p-2.5 rounded-lg text-[11px] text-slate-300 backdrop-blur-xs flex items-center gap-4 flex-wrap">
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-rose-500" />
            <span>Critical Threat</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-amber-500" />
            <span>High Severity</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-sky-400" />
            <span>Medium / Recon</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-cyan-400 border border-white" />
            <span>Protected DC Target</span>
          </div>
        </div>

        {/* Hover / Interactive Tooltip */}
        {hoveredNode && tooltipPos && (
          <div
            className="absolute z-30 pointer-events-none p-3 rounded-lg bg-slate-900/95 border border-slate-700 shadow-xl text-xs space-y-1.5 max-w-xs backdrop-blur-sm"
            style={{
              left: Math.min(tooltipPos.x + 12, (containerRef.current?.clientWidth || 960) - 260),
              top: Math.max(10, tooltipPos.y - 40)
            }}
          >
            <div className="flex items-center justify-between gap-2">
              <span className="font-mono font-bold text-white">{hoveredNode.ip}</span>
              <span className={`text-[10px] font-mono font-bold px-1.5 py-0.2 rounded uppercase ${
                hoveredNode.maxSeverity === 'critical' ? 'text-rose-400 bg-rose-500/10 border border-rose-500/30' : 'text-amber-400 bg-amber-500/10 border border-amber-500/30'
              }`}>
                {hoveredNode.maxSeverity}
              </span>
            </div>

            <div className="text-[11px] text-slate-400">
              <span>{hoveredNode.geo.city}, {hoveredNode.geo.country}</span>
              {hoveredNode.geo.org && (
                <div className="text-[10px] text-slate-500 truncate mt-0.5">{hoveredNode.geo.org}</div>
              )}
            </div>

            <div className="pt-1.5 border-t border-slate-800 text-[11px] flex items-center justify-between text-slate-300 font-mono">
              <span>Events: {hoveredNode.count}</span>
              <span className="text-cyan-400 capitalize">{hoveredNode.categories[0]}</span>
            </div>

            {hoveredNode.isBlocked && (
              <div className="text-[10px] text-rose-400 font-bold tracking-wide">
                BLOCKED AT PERIMETER
              </div>
            )}
          </div>
        )}
      </div>

      {/* Interactive Plotted Threat Origin Focus Bar */}
      <div className="p-3 rounded-xl bg-slate-900/70 border border-slate-800 flex items-center justify-between gap-3 flex-wrap text-xs">
        <div className="flex items-center gap-1.5 text-slate-400 shrink-0">
          <MapPin className="w-3.5 h-3.5 text-cyan-400" />
          <span className="font-semibold text-slate-300">
            {lang === 'pa' ? 'ਨਕਸ਼ੇ ਤੇ ਪਛਾਣ ਕੀਤੇ ਹਮਲਾਵਰ IPs:' : 'Select Attacker IP to Focus:'}
          </span>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          {threatNodes.map((node) => (
            <button
              key={node.ip}
              onClick={() => setSelectedNode(node)}
              className={`px-2.5 py-1 rounded-lg font-mono text-[11px] flex items-center gap-1.5 transition-all border ${
                selectedNode?.ip === node.ip
                  ? 'bg-cyan-500/20 text-cyan-200 border-cyan-500/60 shadow-sm'
                  : 'bg-slate-950 text-slate-300 border-slate-800 hover:border-slate-700 hover:text-white'
              }`}
            >
              <span className={`w-2 h-2 rounded-full ${
                node.maxSeverity === 'critical'
                  ? 'bg-rose-500'
                  : node.maxSeverity === 'high'
                  ? 'bg-amber-500'
                  : 'bg-sky-400'
              }`} />
              <span>{node.ip}</span>
              <span className="text-slate-500 font-sans">({node.geo.countryCode})</span>
              {node.isBlocked && (
                <span className="text-[9px] text-rose-400 font-bold uppercase font-sans">
                  BLK
                </span>
              )}
            </button>
          ))}
        </div>
      </div>

      {/* Selected Node Quick Action Drawer / Card */}
      {selectedNode && (
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-4 animate-in fade-in">
          <div>
            <div className="flex items-center gap-2">
              <Crosshair className="w-4 h-4 text-cyan-400" />
              <span className="text-xs font-bold text-white font-mono">{selectedNode.ip}</span>
              <span className="text-xs text-slate-400">
                ({selectedNode.geo.city}, {selectedNode.geo.country})
              </span>
              {selectedNode.isBlocked && (
                <span className="text-[10px] font-mono text-rose-400 border border-rose-500/30 px-1 py-0.2 rounded">
                  BLOCKED
                </span>
              )}
            </div>
            <div className="text-xs text-slate-400 mt-1 font-mono">
              <span>{selectedNode.count} offensive events detected</span>
              <span className="mx-1.5">·</span>
              <span className="text-slate-300">Vectors: {selectedNode.categories.join(', ')}</span>
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={() => onBlockIp(selectedNode.ip)}
              disabled={selectedNode.isBlocked}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors ${
                selectedNode.isBlocked
                  ? 'bg-slate-800 text-slate-500 cursor-not-allowed'
                  : 'bg-rose-600 hover:bg-rose-500 text-white'
              }`}
            >
              <ShieldX className="w-3.5 h-3.5" />
              <span>{selectedNode.isBlocked ? (lang === 'pa' ? 'ਬਲਾਕਡ ਹੈ' : 'Blocked') : (lang === 'pa' ? 'IP ਬਲਾਕ ਕਰੋ' : 'Block IP')}</span>
            </button>

            {onSelectLog && (
              <button
                onClick={() => onSelectLog(selectedNode.latestLog)}
                className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 flex items-center gap-1.5 transition-colors"
              >
                <ExternalLink className="w-3.5 h-3.5" />
                <span>{lang === 'pa' ? 'ਫੋਰੈਂਸਿਕ ਜਾਂਚ' : 'Inspect Forensics'}</span>
              </button>
            )}

            <button
              onClick={() => setSelectedNode(null)}
              className="px-2.5 py-1.5 rounded-lg text-xs text-slate-400 hover:text-white"
            >
              ✕
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
