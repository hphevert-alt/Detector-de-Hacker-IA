export class TelemetryChart {
  constructor(canvas, options = {}) {
    this.canvas = canvas;
    this.ctx = canvas.getContext('2d');
    this.slotsCount = options.slotsCount || 30;
    this.bucketMs = options.bucketMs || 15_000; // 15s por ciclo (janela de ~7.5 min)
    this.clearedAt = 0;
    this.isActive = true;
    this.logs = [];
    this.hoverIndex = -1;
    this.pulsePhase = 0;
    this.rafId = null;
    this._resizeRaf = null;
    this._lastCssWidth = 0;
    this._lastCssHeight = 0;
    this._lastDpr = 0;
    this.lastPulseFrame = 0;
    this.prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    this.onHoverChange = options.onHoverChange || null;

    this._bindInteractions();
    this._observeResize();
  }

  setActive(active) {
    this.isActive = Boolean(active);
    if (this.isActive && !this.prefersReducedMotion) {
      this._startLoop();
    } else {
      this._stopLoop();
      this.draw();
    }
  }

  setLogs(logs) {
    this.logs = Array.isArray(logs) ? logs : [];
    this.draw();
  }

  clearChartHistory() {
    this.clearedAt = Date.now();
    this.hoverIndex = -1;
    if (this.onHoverChange) this.onHoverChange(null);
    this.draw();
  }

  _startLoop() {
    if (this.rafId !== null) return;
    const tick = (ts) => {
      if (!this.isActive || this.prefersReducedMotion) {
        this.rafId = null;
        return;
      }
      if (ts - this.lastPulseFrame >= 45) {
        this.pulsePhase = (this.pulsePhase + 0.08) % (Math.PI * 2);
        this.lastPulseFrame = ts;
        this.draw();
      }
      this.rafId = window.requestAnimationFrame(tick);
    };
    this.rafId = window.requestAnimationFrame(tick);
  }

  _stopLoop() {
    if (this.rafId !== null) {
      window.cancelAnimationFrame(this.rafId);
      this.rafId = null;
    }
  }

  _observeResize() {
    if (typeof ResizeObserver === 'undefined' || !this.canvas.parentElement) return;
    this._ro = new ResizeObserver(() => {
      if (this._resizeRaf !== null) {
        window.cancelAnimationFrame(this._resizeRaf);
      }
      this._resizeRaf = window.requestAnimationFrame(() => {
        this._resizeRaf = null;
        this.draw();
      });
    });
    this._ro.observe(this.canvas.parentElement);
  }

  _bindInteractions() {
    const updateHover = (clientX) => {
      const rect = this.canvas.getBoundingClientRect();
      if (!rect.width) return;
      const padLeft = 40;
      const padRight = 16;
      const plotW = Math.max(10, rect.width - padLeft - padRight);
      const relX = clientX - rect.left - padLeft;
      if (relX < -8 || relX > plotW + 8) {
        if (this.hoverIndex !== -1) {
          this.hoverIndex = -1;
          if (this.onHoverChange) this.onHoverChange(null);
          this.draw();
        }
        return;
      }
      const clamped = Math.max(0, Math.min(plotW, relX));
      const idx = Math.round((clamped / plotW) * (this.slotsCount - 1));
      if (idx !== this.hoverIndex) {
        this.hoverIndex = idx;
        this.draw();
      }
    };

    this.canvas.addEventListener('mousemove', (e) => updateHover(e.clientX));
    this.canvas.addEventListener(
      'touchstart',
      (e) => {
        if (e.touches[0]) updateHover(e.touches[0].clientX);
      },
      { passive: true }
    );
    this.canvas.addEventListener('mouseleave', () => {
      if (this.hoverIndex !== -1) {
        this.hoverIndex = -1;
        if (this.onHoverChange) this.onHoverChange(null);
        this.draw();
      }
    });
  }

  computeSeries() {
    const now = Date.now();
    const endSlot = Math.floor(now / this.bucketMs);
    const startSlot = endSlot - (this.slotsCount - 1);

    const normal = new Array(this.slotsCount).fill(0);
    const blocked = new Array(this.slotsCount).fill(0);
    const labels = new Array(this.slotsCount);

    for (let i = 0; i < this.slotsCount; i++) {
      const slotTime = (startSlot + i) * this.bucketMs;
      labels[i] = new Date(slotTime).toLocaleTimeString('pt-BR', {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      });
    }

    for (const item of this.logs) {
      if (!item || item.timestamp < this.clearedAt) continue;
      if (item.domain === 'aegis.sistema.local') continue;
      const slot = Math.floor(item.timestamp / this.bucketMs);
      const idx = slot - startSlot;
      if (idx < 0 || idx >= this.slotsCount) continue;

      if (item.action === 'blocked') {
        blocked[idx] += 1;
      } else {
        normal[idx] += 1;
      }
    }

    const totalNormal = normal.reduce((sum, v) => sum + v, 0);
    const totalBlocked = blocked.reduce((sum, v) => sum + v, 0);

    return { normal, blocked, labels, totalNormal, totalBlocked };
  }

  draw() {
    const parent = this.canvas.parentElement;
    const cssWidth = parent ? parent.clientWidth : 640;
    if (cssWidth <= 0) return;

    const cssHeight = window.innerWidth <= 560 ? 200 : 240;
    const dpr = Math.min(window.devicePixelRatio || 1, 3);

    if (
      cssWidth !== this._lastCssWidth ||
      cssHeight !== this._lastCssHeight ||
      dpr !== this._lastDpr
    ) {
      this._lastCssWidth = cssWidth;
      this._lastCssHeight = cssHeight;
      this._lastDpr = dpr;
      this.canvas.style.height = `${cssHeight}px`;
      this.canvas.width = Math.round(cssWidth * dpr);
      this.canvas.height = Math.round(cssHeight * dpr);
    }

    const ctx = this.ctx;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, cssWidth, cssHeight);

    const padLeft = 40;
    const padRight = 16;
    const padTop = 18;
    const padBottom = 28;
    const plotW = Math.max(40, cssWidth - padLeft - padRight);
    const plotH = Math.max(40, cssHeight - padTop - padBottom);

    const series = this.computeSeries();
    const maxRaw = Math.max(4, ...series.normal, ...series.blocked);
    const yMax = Math.ceil(maxRaw / 2) * 2;

    // Background plot area
    ctx.fillStyle = '#090e18';
    ctx.fillRect(padLeft, padTop, plotW, plotH);

    // Reference grid lines (horizontal)
    const gridSteps = 4;
    ctx.font = '500 11px "IBM Plex Mono", monospace';
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';

    for (let s = 0; s <= gridSteps; s++) {
      const ratio = s / gridSteps;
      const y = padTop + plotH - ratio * plotH;
      const val = Math.round(ratio * yMax);

      ctx.beginPath();
      ctx.moveTo(padLeft, y);
      ctx.lineTo(padLeft + plotW, y);
      ctx.strokeStyle =
        s === 0 ? 'rgba(148, 163, 184, 0.28)' : 'rgba(148, 163, 184, 0.1)';
      ctx.lineWidth = 1;
      ctx.stroke();

      ctx.fillStyle = '#64748b';
      ctx.fillText(String(val), padLeft - 8, y);
    }

    // Vertical reference grid + X-axis labels
    const xMarks = [0, 7, 14, 21, 29];
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    for (const idx of xMarks) {
      const x = padLeft + (idx / (this.slotsCount - 1)) * plotW;
      ctx.beginPath();
      ctx.moveTo(x, padTop);
      ctx.lineTo(x, padTop + plotH);
      ctx.strokeStyle = 'rgba(148, 163, 184, 0.08)';
      ctx.lineWidth = 1;
      ctx.stroke();

      const labelText =
        idx === 29
          ? 'Agora'
          : `-${Math.round(((29 - idx) * this.bucketMs) / 60000)}m`;
      ctx.fillStyle = '#64748b';
      const safeX = Math.max(padLeft + 14, Math.min(padLeft + plotW - 14, x));
      ctx.fillText(labelText, safeX, padTop + plotH + 8);
    }

    const getCoords = (values) =>
      values.map((val, i) => ({
        x: padLeft + (i / (this.slotsCount - 1)) * plotW,
        y: padTop + plotH - (val / yMax) * plotH,
        val,
      }));

    const normalPts = getCoords(series.normal);
    const blockedPts = getCoords(series.blocked);

    // Draw smooth area + line helper
    const drawSeries = (pts, strokeColor, fillTop, fillBottom) => {
      if (pts.length < 2) return;

      const traceCurve = () => {
        ctx.moveTo(pts[0].x, pts[0].y);
        for (let i = 0; i < pts.length - 1; i++) {
          const curr = pts[i];
          const next = pts[i + 1];
          const midX = (curr.x + next.x) / 2;
          ctx.bezierCurveTo(midX, curr.y, midX, next.y, next.x, next.y);
        }
      };

      // Area fill
      ctx.beginPath();
      traceCurve();
      ctx.lineTo(pts[pts.length - 1].x, padTop + plotH);
      ctx.lineTo(pts[0].x, padTop + plotH);
      ctx.closePath();

      const grad = ctx.createLinearGradient(0, padTop, 0, padTop + plotH);
      grad.addColorStop(0, fillTop);
      grad.addColorStop(1, fillBottom);
      ctx.fillStyle = grad;
      ctx.fill();

      // Stroke curve
      ctx.beginPath();
      traceCurve();
      ctx.strokeStyle = strokeColor;
      ctx.lineWidth = 2;
      ctx.stroke();
    };

    // Normal traffic (emerald/cyan)
    drawSeries(
      normalPts,
      '#22d3ee',
      'rgba(16, 185, 129, 0.22)',
      'rgba(34, 211, 238, 0.01)'
    );

    // Blocked AI invasions (crimson/amber)
    drawSeries(
      blockedPts,
      '#ef4444',
      'rgba(239, 68, 68, 0.28)',
      'rgba(245, 158, 11, 0.02)'
    );

    // Live trailing pulse dot at "Agora" when VPN is active
    const lastNormal = normalPts[normalPts.length - 1];
    const lastBlocked = blockedPts[blockedPts.length - 1];

    if (this.isActive) {
      const ringRadius = 4 + Math.sin(this.pulsePhase) * 2.5;
      const ringAlpha = 0.45 - Math.sin(this.pulsePhase) * 0.25;

      [
        { pt: lastNormal, color: '#22d3ee', ring: `rgba(34, 211, 238, ${ringAlpha})` },
        { pt: lastBlocked, color: '#f59e0b', ring: `rgba(239, 68, 68, ${ringAlpha})` },
      ].forEach(({ pt, color, ring }) => {
        ctx.beginPath();
        ctx.arc(pt.x, pt.y, Math.max(3, ringRadius), 0, Math.PI * 2);
        ctx.strokeStyle = ring;
        ctx.lineWidth = 1.5;
        ctx.stroke();

        ctx.beginPath();
        ctx.arc(pt.x, pt.y, 3, 0, Math.PI * 2);
        ctx.fillStyle = color;
        ctx.fill();
      });
    } else {
      // Elegant paused indicator overlay
      ctx.fillStyle = 'rgba(8, 12, 20, 0.56)';
      ctx.fillRect(padLeft, padTop, plotW, plotH);

      ctx.font = '600 12px "Plus Jakarta Sans", sans-serif';
      ctx.fillStyle = '#fbbf24';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(
        'Vigilância pausada · telemetria congelada',
        padLeft + plotW / 2,
        padTop + plotH / 2
      );
    }

    // Hover crosshair & active point markers
    if (this.hoverIndex >= 0 && this.hoverIndex < this.slotsCount) {
      const nPt = normalPts[this.hoverIndex];
      const bPt = blockedPts[this.hoverIndex];

      ctx.beginPath();
      ctx.moveTo(nPt.x, padTop);
      ctx.lineTo(nPt.x, padTop + plotH);
      ctx.strokeStyle = 'rgba(241, 245, 249, 0.35)';
      ctx.setLineDash([4, 4]);
      ctx.lineWidth = 1;
      ctx.stroke();
      ctx.setLineDash([]);

      [
        { pt: nPt, color: '#22d3ee' },
        { pt: bPt, color: '#ef4444' },
      ].forEach(({ pt, color }) => {
        ctx.beginPath();
        ctx.arc(pt.x, pt.y, 4.5, 0, Math.PI * 2);
        ctx.fillStyle = color;
        ctx.fill();
        ctx.strokeStyle = '#080c14';
        ctx.lineWidth = 1.5;
        ctx.stroke();
      });

      if (this.onHoverChange) {
        this.onHoverChange({
          time: series.labels[this.hoverIndex],
          normal: nPt.val,
          blocked: bPt.val,
        });
      }
    }

    return series;
  }
}
