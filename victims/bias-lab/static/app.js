window.addEventListener("load", () => {
  document.body.classList.add("loaded");

  const slider = document.querySelector("[data-slider]");
  if (!slider) return;

  const slides = Array.from(slider.querySelectorAll(".slide"));
  const dots = Array.from(slider.querySelectorAll(".dot"));
  const newsButtons = Array.from(slider.querySelectorAll(".news-card"));
  if (slides.length === 0) return;

  let index = 0;

  const setActive = (next) => {
    slides[index].classList.remove("active");
    if (dots[index]) dots[index].classList.remove("active");
    if (newsButtons[index]) newsButtons[index].classList.remove("active");
    index = next;
    slides[index].classList.add("active");
    if (dots[index]) dots[index].classList.add("active");
    if (newsButtons[index]) newsButtons[index].classList.add("active");
  };

  dots.forEach((dot) => {
    dot.addEventListener("click", () => {
      const next = Number(dot.dataset.slide || 0);
      setActive(next);
    });
  });

  newsButtons.forEach((btn) => {
    btn.addEventListener("click", (event) => {
      if (event.target.closest(".news-action")) return;
      const next = Number(btn.dataset.slide || 0);
      setActive(next);
    });
    btn.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        const next = Number(btn.dataset.slide || 0);
        setActive(next);
      }
    });
  });

  setInterval(() => {
    const next = (index + 1) % slides.length;
    setActive(next);
  }, 5000);
});
