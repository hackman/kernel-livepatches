/* Matrix digital-rain background.
 * Lightweight canvas renderer: katakana + digits + a few symbols,
 * leading glyph is bright, trailing glyphs fade to deep green. */
(function () {
	var canvas = document.getElementById("matrix-rain");
	if (!canvas) return;
	var ctx = canvas.getContext("2d", { alpha: false });

	var GLYPHS =
		"\u30A2\u30AB\u30B5\u30BF\u30CA\u30CF\u30DE\u30E4\u30E9\u30EF" +
		"\u30A4\u30AD\u30B7\u30C1\u30CB\u30D2\u30DF\u30EA\u30F0" +
		"\u30A6\u30AF\u30B9\u30C4\u30CC\u30D5\u30E0\u30E6\u30EB" +
		"0123456789" +
		"\uFF21\uFF22\uFF23\uFF24\uFF25\uFF26" +
		"<>/\\|=+*#$%&";
	var chars = GLYPHS.split("");

	var fontSize = 16;
	var columns = 0;
	var drops = [];
	var W = 0, H = 0, dpr = 1;

	function reset() {
		dpr = Math.min(window.devicePixelRatio || 1, 2);
		W = window.innerWidth;
		H = window.innerHeight;
		canvas.width = Math.floor(W * dpr);
		canvas.height = Math.floor(H * dpr);
		canvas.style.width = W + "px";
		canvas.style.height = H + "px";
		ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
		columns = Math.floor(W / fontSize);
		drops = new Array(columns);
		for (var i = 0; i < columns; i++) {
			drops[i] = Math.floor(Math.random() * -50);
		}
		ctx.fillStyle = "#000400";
		ctx.fillRect(0, 0, W, H);
	}

	function draw() {
		// translucent black to create the fading trail (higher alpha =
		// shorter, dimmer trails)
		ctx.fillStyle = "rgba(0, 4, 0, 0.14)";
		ctx.fillRect(0, 0, W, H);
		ctx.font = fontSize + "px monospace";

		for (var i = 0; i < columns; i++) {
			var x = i * fontSize;
			var y = drops[i] * fontSize;
			var ch = chars[(Math.random() * chars.length) | 0];

			if (y > 0) {
				// leading glyph (dimmed)
				ctx.fillStyle = "#6fcf88";
				ctx.shadowColor = "#0a7d28";
				ctx.shadowBlur = 4;
				ctx.fillText(ch, x, y);

				// a dimmer glyph just behind the head
				ctx.shadowBlur = 0;
				ctx.fillStyle = "#0b7a27";
				ctx.fillText(chars[(Math.random() * chars.length) | 0], x, y - fontSize);
			}

			if (y > H && Math.random() > 0.975) {
				drops[i] = Math.floor(Math.random() * -20);
			}
			drops[i]++;
		}
		ctx.shadowBlur = 0;
	}

	var raf, interval;
	function start() {
		stop();
		// ~20fps is plenty for rain and keeps CPU low
		interval = setInterval(draw, 50);
	}
	function stop() {
		if (interval) clearInterval(interval);
		if (raf) cancelAnimationFrame(raf);
	}

	var resizeTimer;
	window.addEventListener("resize", function () {
		clearTimeout(resizeTimer);
		resizeTimer = setTimeout(reset, 150);
	});
	document.addEventListener("visibilitychange", function () {
		if (document.hidden) stop(); else start();
	});
	// Respect reduced-motion: render one static frame only.
	var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

	reset();
	if (reduce) { for (var k = 0; k < 40; k++) draw(); }
	else start();
})();
