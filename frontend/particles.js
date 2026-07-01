/* ============================================================
   SecureAI X — Scroll-driven 3D particle engine
   One glowing point cloud morphs between shapes as the page
   scrolls: Globe (hero) -> Shield (scanner) -> Bar chart
   (analytics) -> Attack burst (simulator) -> Document (reports)
   -> Dust (footer). Between any two shapes the particles fly
   outward into scattered dust before reassembling, driven by a
   fixed per-particle offset scaled by sin(pi * t).
   ============================================================ */

(function () {
  const canvas = document.getElementById("particles");
  if (!canvas || !window.THREE) return;

  const COUNT = 3200;
  const GROUP_OFFSET_X = 2.4; // keep the shape in the right-hand column like the reference

  const COLOR = {
    globe: new THREE.Color(0x00e08a),
    shield: new THREE.Color(0x00ffb2),
    chart: new THREE.Color(0x00d4ff),
    burst: new THREE.Color(0xff5d3b),
    doc: new THREE.Color(0x3fd6a0),
    dust: new THREE.Color(0x14513b),
  };
  const SHAPE_ORDER = ["globe", "shield", "chart", "burst", "doc", "dust"];

  // ---------------------------------------------------------------
  // Shape generators — each returns a Float32Array(COUNT*3)
  // ---------------------------------------------------------------

  function shapeGlobe() {
    const arr = new Float32Array(COUNT * 3);
    const golden = Math.PI * (3 - Math.sqrt(5));
    const r = 3.0;
    for (let i = 0; i < COUNT; i++) {
      const y = 1 - (i / (COUNT - 1)) * 2;
      const rad = Math.sqrt(Math.max(0, 1 - y * y));
      const theta = golden * i;
      const jitter = 1 + (Math.random() - 0.5) * 0.02;
      arr[i * 3] = Math.cos(theta) * rad * r * jitter;
      arr[i * 3 + 1] = y * r * jitter;
      arr[i * 3 + 2] = Math.sin(theta) * rad * r * jitter;
    }
    return arr;
  }

  function insideShield(x, y) {
    if (y >= 0.9) return x * x + (y - 0.9) * (y - 0.9) <= 1.4 * 1.4;
    if (y < -1.8) return false;
    const t = (y + 1.8) / (0.9 + 1.8); // 0 at bottom point, 1 near cap
    const widthAtY = 1.4 * t;
    return Math.abs(x) <= widthAtY;
  }

  function shapeShield() {
    const arr = new Float32Array(COUNT * 3);
    let i = 0;
    let guard = 0;
    while (i < COUNT && guard < COUNT * 60) {
      guard++;
      const x = (Math.random() - 0.5) * 3.2;
      const y = Math.random() * 3.4 - 1.9;
      if (insideShield(x, y)) {
        arr[i * 3] = x * 1.55;
        arr[i * 3 + 1] = y * 1.35;
        arr[i * 3 + 2] = (Math.random() - 0.5) * 0.5;
        i++;
      }
    }
    // fill any remainder (guard exhausted) with center noise
    for (; i < COUNT; i++) {
      arr[i * 3] = (Math.random() - 0.5) * 0.4;
      arr[i * 3 + 1] = (Math.random() - 0.5) * 0.4;
      arr[i * 3 + 2] = (Math.random() - 0.5) * 0.4;
    }
    return arr;
  }

  // exposed so app.js can rebuild with real severity counts
  let lastCounts = { critical: 3, high: 4, medium: 2, low: 1 };
  function shapeChart(counts) {
    counts = counts || lastCounts;
    lastCounts = counts;
    const arr = new Float32Array(COUNT * 3);
    const bars = [
      { h: Math.max(0.3, counts.critical), x: -2.1 },
      { h: Math.max(0.3, counts.high), x: -1.05 },
      { h: Math.max(0.3, counts.medium), x: 0.05 },
      { h: Math.max(0.3, counts.low), x: 1.1 },
      { h: Math.max(0.3, (counts.critical + counts.high + counts.medium + counts.low) / 2), x: 2.15 },
    ];
    const maxH = Math.max(...bars.map((b) => b.h), 1);
    for (let i = 0; i < COUNT; i++) {
      const bar = bars[i % bars.length];
      const scaledH = 0.6 + (bar.h / maxH) * 3.2;
      arr[i * 3] = bar.x + (Math.random() - 0.5) * 0.55;
      arr[i * 3 + 1] = Math.random() * scaledH - 1.7;
      arr[i * 3 + 2] = (Math.random() - 0.5) * 0.5;
    }
    return arr;
  }

  function shapeBurst() {
    const arr = new Float32Array(COUNT * 3);
    const spikes = 14;
    for (let i = 0; i < COUNT; i++) {
      const spike = i % spikes;
      const angle = (spike / spikes) * Math.PI * 2 + Math.sin(spike) * 0.15;
      const tilt = (Math.random() - 0.5) * 0.6;
      const reach = 0.4 + Math.random() * 3.1;
      const dirX = Math.cos(angle);
      const dirY = Math.sin(angle) * 0.75 + tilt * 0.3;
      const dirZ = Math.sin(angle * 1.3) * 0.6;
      const spread = (Math.random() - 0.5) * 0.18 * reach;
      arr[i * 3] = dirX * reach + spread;
      arr[i * 3 + 1] = dirY * reach + spread;
      arr[i * 3 + 2] = dirZ * reach + spread;
    }
    return arr;
  }

  function shapeDoc() {
    const arr = new Float32Array(COUNT * 3);
    const w = 2.0, h = 2.9;
    const lineCount = 8;
    const perLine = Math.floor(COUNT * 0.65 / lineCount);
    let i = 0;
    for (let l = 0; l < lineCount && i < COUNT; l++) {
      const y = h / 2 - 0.35 - l * (h / (lineCount + 1));
      const lineLen = w * (0.4 + (l % 3) * 0.22);
      for (let k = 0; k < perLine && i < COUNT; k++, i++) {
        arr[i * 3] = -w / 2 + Math.random() * lineLen;
        arr[i * 3 + 1] = y + (Math.random() - 0.5) * 0.05;
        arr[i * 3 + 2] = (Math.random() - 0.5) * 0.15;
      }
    }
    // remaining particles trace the page border
    const remaining = COUNT - i;
    for (let k = 0; k < remaining; k++, i++) {
      const edge = k % 4;
      let x, y;
      if (edge === 0) { x = -w / 2 + Math.random() * w; y = h / 2; }
      else if (edge === 1) { x = -w / 2 + Math.random() * w; y = -h / 2; }
      else if (edge === 2) { x = -w / 2; y = -h / 2 + Math.random() * h; }
      else { x = w / 2; y = -h / 2 + Math.random() * h; }
      arr[i * 3] = x;
      arr[i * 3 + 1] = y;
      arr[i * 3 + 2] = (Math.random() - 0.5) * 0.15;
    }
    return arr;
  }

  function shapeDust() {
    const arr = new Float32Array(COUNT * 3);
    for (let i = 0; i < COUNT; i++) {
      const r = 4 + Math.random() * 4;
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.acos(2 * Math.random() - 1);
      arr[i * 3] = r * Math.sin(phi) * Math.cos(theta);
      arr[i * 3 + 1] = r * Math.sin(phi) * Math.sin(theta);
      arr[i * 3 + 2] = r * Math.cos(phi) * 0.4;
    }
    return arr;
  }

  const SHAPES = {
    globe: shapeGlobe(),
    shield: shapeShield(),
    chart: shapeChart(),
    burst: shapeBurst(),
    doc: shapeDoc(),
    dust: shapeDust(),
  };

  // fixed per-particle scatter direction, used on every transition
  const SCATTER = new Float32Array(COUNT * 3);
  for (let i = 0; i < COUNT * 3; i += 3) {
    const r = 3 + Math.random() * 5;
    const theta = Math.random() * Math.PI * 2;
    const phi = Math.acos(2 * Math.random() - 1);
    SCATTER[i] = r * Math.sin(phi) * Math.cos(theta);
    SCATTER[i + 1] = r * Math.sin(phi) * Math.sin(theta);
    SCATTER[i + 2] = r * Math.cos(phi);
  }

  // ---------------------------------------------------------------
  // Scene setup
  // ---------------------------------------------------------------

  let renderer, scene, camera, group, points, geo, posAttr;
  let width, height;

  function init() {
    width = window.innerWidth;
    height = window.innerHeight;

    renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: true });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.setSize(width, height);

    scene = new THREE.Scene();
    camera = new THREE.PerspectiveCamera(48, width / height, 0.1, 100);
    camera.position.set(0, 0.2, 9.5);

    group = new THREE.Group();
    group.position.x = GROUP_OFFSET_X;
    scene.add(group);

    geo = new THREE.BufferGeometry();
    posAttr = new THREE.Float32BufferAttribute(new Float32Array(SHAPES.globe), 3);
    geo.setAttribute("position", posAttr);

    const mat = new THREE.PointsMaterial({
      size: 0.045,
      color: COLOR.globe.getHex(),
      transparent: true,
      opacity: 0.85,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    });
    points = new THREE.Points(geo, mat);
    group.add(points);

    // pedestal glow rings (only meaningful for the hero globe)
    const rings = [];
    for (let i = 0; i < 3; i++) {
      const ringGeo = new THREE.RingGeometry(2.1 + i * 0.55, 2.16 + i * 0.55, 64);
      const ringMat = new THREE.MeshBasicMaterial({
        color: COLOR.globe.getHex(), transparent: true, opacity: 0.18 - i * 0.04,
        side: THREE.DoubleSide, blending: THREE.AdditiveBlending, depthWrite: false,
      });
      const ring = new THREE.Mesh(ringGeo, ringMat);
      ring.rotation.x = Math.PI / 2;
      ring.position.set(GROUP_OFFSET_X, -3.4, 0);
      scene.add(ring);
      rings.push(ring);
    }

    window._secureaiRings = rings;
    window.addEventListener("resize", onResize);
    animate();
  }

  function onResize() {
    width = window.innerWidth;
    height = window.innerHeight;
    camera.aspect = width / height;
    camera.updateProjectionMatrix();
    renderer.setSize(width, height);
  }

  function easeInOutCubic(t) {
    return t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2;
  }

  let t = 0;
  function animate() {
    requestAnimationFrame(animate);
    t += 0.003;

    updateFromScroll();

    group.rotation.y = t * 0.6;
    group.rotation.x = Math.sin(t * 0.4) * 0.1;

    renderer.render(scene, camera);
  }

  function updateFromScroll() {
    const maxScroll = Math.max(1, document.documentElement.scrollHeight - window.innerHeight);
    const globalT = Math.min(1, Math.max(0, window.scrollY / maxScroll));
    const segCount = SHAPE_ORDER.length - 1;
    const segF = globalT * segCount;
    const segIndex = Math.min(segCount - 1, Math.floor(segF));
    const localT = easeInOutCubic(segF - segIndex);

    const fromKey = SHAPE_ORDER[segIndex];
    const toKey = SHAPE_ORDER[segIndex + 1];
    const from = SHAPES[fromKey];
    const to = SHAPES[toKey];
    const scatterFactor = Math.sin(Math.PI * localT) * 0.9; // peak mid-transition

    const arr = posAttr.array;
    for (let i = 0; i < COUNT * 3; i++) {
      const base = from[i] + (to[i] - from[i]) * localT;
      arr[i] = base + SCATTER[i] * scatterFactor * (i % 3 === 2 ? 0.3 : 1);
    }
    posAttr.needsUpdate = true;

    // color lerp
    const c = COLOR[fromKey].clone().lerp(COLOR[toKey], localT);
    points.material.color.copy(c);

    // pedestal rings only visible near the hero globe
    const ringOpacityScale = segIndex === 0 ? 1 - localT : 0;
    if (window._secureaiRings) {
      window._secureaiRings.forEach((ring, i) => {
        ring.material.opacity = (0.18 - i * 0.04) * ringOpacityScale;
      });
    }
  }

  // called by app.js once real scan data is available
  window.updateAnalyticsShape = function (counts) {
    SHAPES.chart = shapeChart(counts);
  };

  if (document.readyState === "complete" || document.readyState === "interactive") {
    setTimeout(init, 0);
  } else {
    document.addEventListener("DOMContentLoaded", init);
  }
})();
