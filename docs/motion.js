const { gsap, ScrollTrigger, SplitText } = window;

if (gsap && ScrollTrigger && SplitText) {
  gsap.registerPlugin(ScrollTrigger, SplitText);

  const mm = gsap.matchMedia();
  mm.add("(prefers-reduced-motion: no-preference)", () => {
    document.documentElement.classList.add("motion");
    const ease = "expo.out";

    // ------------------------------------------------------------------ intro
    const intro = gsap.timeline({ defaults: { ease } });

    intro.from(".frame, .frame i", { scaleY: 0, transformOrigin: "50% 0%", duration: 1.4, stagger: 0.06, ease: "power3.inOut" }, 0);
    intro.from(".site-header > *", { autoAlpha: 0, y: -10, duration: 0.8, stagger: 0.06 }, 0.1);

    const h1 = document.querySelector(".hero h1");
    if (h1) {
      const split = SplitText.create(h1, { type: "lines", mask: "lines", linesClass: "line" });
      intro.from(split.lines, { yPercent: 110, duration: 1.1, stagger: 0.09 }, 0.25);
    }
    intro.from(".hero .lede", { autoAlpha: 0, y: 18, duration: 0.9 }, 0.55);
    intro.from(".cta-row", { autoAlpha: 0, x: -14, duration: 0.7, stagger: 0.07 }, 0.7);

    intro.from(".cf-win", { autoAlpha: 0, y: 48, rotateX: 10, transformPerspective: 1400, transformOrigin: "50% 100%", duration: 1.1 }, 0.4);
    intro.from(".cf-lines li.b, .cf-lines li.e", { autoAlpha: 0, x: -6, duration: 0.3, stagger: 0.05 }, 0.75);
    intro.from(".cf-lines li.s1", { autoAlpha: 0, x: -6, duration: 0.25, stagger: 0.04 }, 1.1);
    intro.from(".br1", { scaleY: 0, transformOrigin: "50% 0%", duration: 0.5, ease: "power2.out" }, 1.3);
    intro.from(".cf-lines li.s2", { autoAlpha: 0, x: -6, duration: 0.25, stagger: 0.04 }, 1.55);
    intro.from(".br2", { scaleY: 0, transformOrigin: "50% 0%", duration: 0.6, ease: "power2.out" }, 1.75);
    intro.from(".hid", { autoAlpha: 0, duration: 0.5 }, 2.0);

    intro.fromTo(
      ".seal",
      { autoAlpha: 0, scale: 1.9, rotate: -32, y: -18 },
      { autoAlpha: 1, scale: 1, rotate: -9, y: 0, duration: 0.55, ease: "back.out(2.2)" },
      2.15,
    );
    intro.fromTo(".cf-win", { y: 0 }, { y: 3, duration: 0.08, yoyo: true, repeat: 1, ease: "power1.inOut" }, 2.42);
    intro.from(".hero-figure figcaption", { autoAlpha: 0, y: 8, duration: 0.7 }, 2.3);
    intro.from(".facts > div", { autoAlpha: 0, y: 20, duration: 0.9, stagger: 0.08 }, 0.9);

    gsap.to(".hero-figure", {
      y: -60,
      ease: "none",
      scrollTrigger: { trigger: ".intro", start: "top top", end: "bottom top", scrub: 0.6 },
    });
    gsap.to(".hero-beam", {
      xPercent: 8,
      yPercent: 6,
      ease: "none",
      scrollTrigger: { trigger: ".intro", start: "top top", end: "bottom top", scrub: 0.6 },
    });

    // ------------------------------------------------------------------ slides
    const reveal = (selector, vars) =>
      gsap.utils.toArray(selector).forEach((el) =>
        gsap.from(el, { autoAlpha: 0, y: 28, duration: 1, ease, ...vars, scrollTrigger: { trigger: el, start: "top 82%", once: true } }),
      );

    for (const head of gsap.utils.toArray(".slide .section-head h2")) {
      const split = SplitText.create(head, { type: "lines", mask: "lines" });
      gsap.from(split.lines, { yPercent: 110, duration: 1, ease, stagger: 0.08, scrollTrigger: { trigger: head, start: "top 85%", once: true } });
    }
    reveal(".slide .section-head p", { y: 14, duration: 0.8 });

    gsap.from(".playground", { autoAlpha: 0, y: 40, scale: 0.985, duration: 1.1, ease, scrollTrigger: { trigger: ".playground", start: "top 85%", once: true } });

    gsap.from(".why-list li", { autoAlpha: 0, y: 18, duration: 0.8, ease, stagger: 0.06, scrollTrigger: { trigger: ".why-list", start: "top 82%", once: true } });
    gsap.from(".steps li", { autoAlpha: 0, x: -24, duration: 0.9, ease, stagger: 0.12, scrollTrigger: { trigger: ".steps", start: "top 80%", once: true } });
    const code = document.querySelector(".sig-example code");
    if (code) {
      code.innerHTML = code.innerHTML.split("\n").map((l) => `<span class="code-line">${l || " "}</span>`).join("\n");
      gsap.from(code.querySelectorAll(".code-line"), { autoAlpha: 0, x: -8, duration: 0.35, ease: "power2.out", stagger: 0.045, scrollTrigger: { trigger: code, start: "top 80%", once: true } });
    }

    gsap.from("tbody tr", { autoAlpha: 0, y: 14, duration: 0.7, ease, stagger: 0.06, scrollTrigger: { trigger: "table", start: "top 80%", once: true } });

    gsap.from(".start-grid > div", { autoAlpha: 0, y: 24, duration: 0.9, ease, stagger: 0.12, scrollTrigger: { trigger: ".start-grid", start: "top 82%", once: true } });

    return () => document.documentElement.classList.remove("motion");
  });

  document.fonts?.ready.then(() => ScrollTrigger.refresh());
}
