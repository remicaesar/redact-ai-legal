/* Landing page motion: scroll progress, reveal-on-scroll, rotating word, and the
   ambient particle field. Plain DOM -- the source design was a React export, but
   the app ships no framework and a marketing page is not a reason to add one.

   Every effect is decorative. When the visitor asks for reduced motion we skip
   the particle loop entirely (it is a permanent rAF) and leave content visible. */

(function () {
    "use strict";

    var reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    /* --- scroll progress ------------------------------------------------- */

    function initProgress() {
        var bar = document.querySelector("[data-progress]");
        if (!bar) return;

        function update() {
            var doc = document.documentElement;
            var max = doc.scrollHeight - doc.clientHeight;
            var pct = max > 0 ? Math.min(1, Math.max(0, window.scrollY / max)) * 100 : 0;
            bar.style.width = pct.toFixed(2) + "%";
        }

        window.addEventListener("scroll", update, { passive: true });
        window.addEventListener("resize", update);
        update();
    }

    /* --- reveal on scroll ------------------------------------------------ */

    function initReveal() {
        var nodes = Array.prototype.slice.call(document.querySelectorAll("[data-reveal]"));
        if (!nodes.length) return;

        if (reduceMotion || !("IntersectionObserver" in window)) {
            nodes.forEach(function (el) { el.classList.add("is-revealed"); });
            return;
        }

        var observer = new IntersectionObserver(function (entries) {
            entries.forEach(function (entry) {
                if (!entry.isIntersecting) return;
                var el = entry.target;
                el.style.transitionDelay = (parseFloat(el.dataset.reveal) || 0) + "ms";
                el.classList.add("is-revealed");
                observer.unobserve(el);
            });
        }, { rootMargin: "0px 0px -6% 0px" });

        nodes.forEach(function (el) { observer.observe(el); });
    }

    /* --- workflow connector ---------------------------------------------- */

    function initWorkflowLine() {
        var line = document.querySelector("[data-grow]");
        if (!line) return;

        if (reduceMotion || !("IntersectionObserver" in window)) {
            line.style.width = "100%";
            return;
        }

        var observer = new IntersectionObserver(function (entries) {
            entries.forEach(function (entry) {
                if (!entry.isIntersecting) return;
                line.style.width = "100%";
                observer.unobserve(entry.target);
            });
        }, { threshold: 0.35 });

        observer.observe(line.parentElement);
    }

    /* --- rotating capability word ---------------------------------------- */

    function initRotator() {
        var el = document.querySelector("[data-rotator]");
        if (!el) return;

        var words;
        try {
            words = JSON.parse(el.getAttribute("data-rotator"));
        } catch (err) {
            return;
        }
        if (!Array.isArray(words) || words.length < 2) return;

        var index = 0;
        el.textContent = words[0];
        if (reduceMotion) return;

        setInterval(function () {
            el.classList.add("is-swapping");
            setTimeout(function () {
                index = (index + 1) % words.length;
                el.textContent = words[index];
                el.classList.remove("is-swapping");
            }, 400);
        }, 2400);
    }

    /* --- ambient particles ----------------------------------------------- */

    function initParticles() {
        var canvas = document.querySelector("[data-particles]");
        if (!canvas || reduceMotion) return;

        var ctx = canvas.getContext("2d");
        if (!ctx) return;

        var width = 0;
        var height = 0;
        var particles = [];
        var mouse = { x: -9999, y: -9999 };
        var colors = ["110,42,50", "61,107,78", "126,52,61"];

        function resize() {
            var dpr = window.devicePixelRatio || 1;
            width = canvas.clientWidth || window.innerWidth;
            height = canvas.clientHeight || window.innerHeight;
            canvas.width = width * dpr;
            canvas.height = height * dpr;
            ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        }

        function seed() {
            // Scale the count to the viewport so phones do not pay for a
            // desktop-sized field.
            var count = Math.min(180, Math.round((width * height) / 11000));
            particles = [];
            for (var i = 0; i < count; i++) {
                particles.push({
                    x: Math.random() * width,
                    y: Math.random() * height,
                    vx: (Math.random() - 0.5) * 0.18,
                    vy: (Math.random() - 0.5) * 0.18,
                    r: Math.random() * 1.6 + 0.7,
                    c: colors[Math.floor(Math.random() * colors.length)]
                });
            }
        }

        function draw() {
            ctx.clearRect(0, 0, width, height);

            if (mouse.x > -100) {
                var glow = ctx.createRadialGradient(mouse.x, mouse.y, 0, mouse.x, mouse.y, 260);
                glow.addColorStop(0, "rgba(110,42,50,0.10)");
                glow.addColorStop(0.5, "rgba(61,107,78,0.05)");
                glow.addColorStop(1, "rgba(110,42,50,0)");
                ctx.fillStyle = glow;
                ctx.fillRect(0, 0, width, height);
            }

            for (var i = 0; i < particles.length; i++) {
                var p = particles[i];
                var dx = p.x - mouse.x;
                var dy = p.y - mouse.y;
                var dist = Math.sqrt(dx * dx + dy * dy) || 1;
                var influence = Math.max(0, 1 - dist / 170);

                if (influence > 0) {
                    p.x += (dx / dist) * influence * 1.3;
                    p.y += (dy / dist) * influence * 1.3;
                }
                p.x += p.vx;
                p.y += p.vy;

                if (p.x < 0) p.x = width; else if (p.x > width) p.x = 0;
                if (p.y < 0) p.y = height; else if (p.y > height) p.y = 0;

                ctx.beginPath();
                ctx.arc(p.x, p.y, p.r + influence * 1.6, 0, Math.PI * 2);
                ctx.fillStyle = "rgba(" + p.c + "," + (0.18 + influence * 0.55) + ")";
                ctx.fill();
            }

            requestAnimationFrame(draw);
        }

        resize();
        seed();
        window.addEventListener("resize", function () { resize(); seed(); });
        document.addEventListener("mousemove", function (event) {
            var rect = canvas.getBoundingClientRect();
            mouse.x = event.clientX - rect.left;
            mouse.y = event.clientY - rect.top;
        }, { passive: true });
        document.addEventListener("mouseleave", function () {
            mouse.x = -9999;
            mouse.y = -9999;
        });

        draw();
    }

    function init() {
        initProgress();
        initReveal();
        initWorkflowLine();
        initRotator();
        initParticles();
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
