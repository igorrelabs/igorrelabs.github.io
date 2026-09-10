(() => {
  const CONTAINER_SELECTOR = ".glightbox-container";
  const BUTTON_CLASS = "gzoom-custom";

  const MIN_SCALE = 1;
  const CLICK_SCALE = 2;
  const MAX_SCALE = 4;
  const WHEEL_SENSITIVITY = 0.0015;

  const states = new WeakMap();

  function clamp(value, minimum, maximum) {
    return Math.min(maximum, Math.max(minimum, value));
  }

  function getLabels() {
    const portuguese = (document.documentElement.lang || "")
      .toLowerCase()
      .startsWith("ptbr");

    return portuguese
      ? {
          zoomIn: "Ampliar imagem",
          zoomOut: "Restaurar imagem"
        }
      : {
          zoomIn: "Zoom in",
          zoomOut: "Reset image zoom"
        };
  }

  function getActiveSlide(container) {
    return container.querySelector(".gslide.current");
  }

  function getActiveImage(container) {
    return getActiveSlide(container)?.querySelector(
      ".gslide-media img"
    ) || null;
  }

  function restoreStyle(element, originalStyle) {
    if (!element) {
      return;
    }

    if (originalStyle === null) {
      element.removeAttribute("style");
    } else {
      element.setAttribute("style", originalStyle);
    }
  }

  function getState(container) {
    const slide = getActiveSlide(container);
    const image = getActiveImage(container);
    const media = image?.closest(".gslide-media");

    if (!slide || !image || !media) {
      return null;
    }

    let state = states.get(slide);

    if (!state || state.image !== image) {
      state = {
        container,
        slide,
        image,
        media,

        scale: MIN_SCALE,
        x: 0,
        y: 0,

        baseWidth: 0,
        baseHeight: 0,

        dragging: false,
        moved: false,
        suppressClick: false,
        pointerId: null,

        dragStartX: 0,
        dragStartY: 0,
        initialX: 0,
        initialY: 0,

        originalImageStyle: image.getAttribute("style")
      };

      states.set(slide, state);
    }

    return state;
  }

  function activateZoomContext(state) {
    if (state.slide.classList.contains("custom-zoom-context")) {
      return true;
    }

    if (
      !state.image.complete ||
      state.image.naturalWidth === 0 ||
      state.image.naturalHeight === 0
    ) {
      state.image.addEventListener(
        "load",
        () => {
          activateZoomContext(state);
          syncButton(state.container);
        },
        { once: true }
      );

      return false;
    }

    state.slide.classList.add("custom-zoom-context");

    /*
     * Remove qualquer transformação anterior apenas durante
     * a medição do tamanho base centralizado.
     */
    state.image.style.transition = "none";
    state.image.style.transformOrigin = "center center";
    state.image.style.transform =
      "translate3d(0px, 0px, 0) scale(1)";

    const rect = state.image.getBoundingClientRect();

    state.baseWidth = rect.width;
    state.baseHeight = rect.height;

    return state.baseWidth > 0 && state.baseHeight > 0;
  }

  function deactivateZoomContext(state) {
  if (!state) {
    return;
  }

  restoreStyle(
    state.image,
    state.originalImageStyle
  );

  state.image.classList.remove("is-custom-panning");

  state.slide.classList.remove(
    "custom-zoom-context",
    "custom-zoomed"
  );

  state.scale = MIN_SCALE;
  state.x = 0;
  state.y = 0;

  state.baseWidth = 0;
  state.baseHeight = 0;

  state.dragging = false;
  state.moved = false;
  state.pointerId = null;
}

  function getPanBounds(state) {
    const visibleWidth = state.baseWidth * state.scale;
    const visibleHeight = state.baseHeight * state.scale;

    return {
      maxX: Math.max(
        0,
        (visibleWidth - state.media.clientWidth) / 2
      ),
      maxY: Math.max(
        0,
        (visibleHeight - state.media.clientHeight) / 2
      )
    };
  }

  function clampPosition(state) {
    const { maxX, maxY } = getPanBounds(state);

    state.x = clamp(state.x, -maxX, maxX);
    state.y = clamp(state.y, -maxY, maxY);
  }

  function applyTransform(state, animate = false) {
  const zoomed =
    state.scale > MIN_SCALE + 0.001;

  /*
   * Ao retornar para 1×, removemos o contexto que fazia
   * o slide ocupar toda a viewport. Assim, o clique externo
   * volta a ser processado normalmente pelo GLightbox.
   */
  if (!zoomed) {
    deactivateZoomContext(state);
    syncButton(state.container);
    return;
  }

  if (!activateZoomContext(state)) {
    return;
  }

  clampPosition(state);

  state.image.style.transition = animate
    ? "transform 180ms ease"
    : "none";

  state.image.style.transformOrigin = "center center";

  state.image.style.transform =
    `translate3d(${state.x}px, ${state.y}px, 0) ` +
    `scale(${state.scale})`;

  state.slide.classList.add(
    "custom-zoom-context",
    "custom-zoomed"
  );

  state.image.classList.toggle(
    "is-custom-panning",
    state.dragging
  );

  syncButton(state.container);
}

  function setScale(
    state,
    requestedScale,
    anchor = null,
    animate = false
  ) {
    if (!activateZoomContext(state)) {
      return;
    }

    const previousScale = state.scale;
    const nextScale = clamp(
      requestedScale,
      MIN_SCALE,
      MAX_SCALE
    );

    if (anchor && previousScale > 0) {
      const ratio = nextScale / previousScale;

      /*
       * Mantém sob o cursor o mesmo ponto da imagem
       * durante o zoom feito pela roda do mouse.
       */
      state.x =
        anchor.x - (anchor.x - state.x) * ratio;

      state.y =
        anchor.y - (anchor.y - state.y) * ratio;
    } else if (previousScale <= MIN_SCALE + 0.001) {
      /*
       * O zoom por clique ou botão sempre começa centralizado.
       */
      state.x = 0;
      state.y = 0;
    }

    state.scale = nextScale;

    if (nextScale <= MIN_SCALE + 0.001) {
      state.scale = MIN_SCALE;
      state.x = 0;
      state.y = 0;
    }

    applyTransform(state, animate);
  }

  function toggleZoom(state) {
    if (state.scale > MIN_SCALE + 0.001) {
      setScale(state, MIN_SCALE, null, true);
    } else {
      state.x = 0;
      state.y = 0;
      setScale(state, CLICK_SCALE, null, true);
    }
  }

  function resetState(state) {
  if (!state) {
    return;
  }

  deactivateZoomContext(state);
  states.delete(state.slide);
}

  function resetInactiveSlides(container) {
    const current = getActiveSlide(container);

    container
      .querySelectorAll(".gslide.custom-zoom-context")
      .forEach(slide => {
        if (slide !== current) {
          resetState(states.get(slide));
        }
      });

    if (!current) {
      container
        .querySelectorAll(".gslide")
        .forEach(slide => {
          resetState(states.get(slide));
        });
    }
  }

  function syncButton(container) {
    const button = container.querySelector(
      `.${BUTTON_CLASS}`
    );

    if (!button) {
      return;
    }

    const state = getState(container);
    const available =
      Boolean(state) && window.innerWidth > 768;

    button.hidden = !available;

    if (!state) {
      return;
    }

    const zoomed = state.scale > MIN_SCALE + 0.001;
    const labels = getLabels();
    const label = zoomed
      ? labels.zoomOut
      : labels.zoomIn;

    button.setAttribute("aria-label", label);
    button.setAttribute("title", label);
    button.setAttribute(
      "aria-pressed",
      String(zoomed)
    );

    const icon = button.querySelector("i");

    if (icon) {
      icon.classList.toggle(
        "fa-magnifying-glass-plus",
        !zoomed
      );

      icon.classList.toggle(
        "fa-magnifying-glass-minus",
        zoomed
      );
    }
  }

  function createButton(container) {
    const controls = container.querySelector(".gcontainer");

    if (!controls) {
      return null;
    }

    const existing = controls.querySelector(
      `.${BUTTON_CLASS}`
    );

    if (existing) {
      return existing;
    }

    const button = document.createElement("button");

    button.type = "button";
    button.className = `${BUTTON_CLASS} gbtn`;
    button.hidden = true;

    button.innerHTML = `
      <i
        class="fa-solid fa-magnifying-glass-plus"
        aria-hidden="true"
      ></i>
    `;

    const closeButton = controls.querySelector(".gclose");

    if (closeButton) {
      controls.insertBefore(button, closeButton);
    } else {
      controls.appendChild(button);
    }

    button.addEventListener("click", event => {
      event.preventDefault();
      event.stopPropagation();
      event.stopImmediatePropagation();

      const state = getState(container);

      if (state) {
        toggleZoom(state);
      }
    });

    return button;
  }

  function installImageClick(container) {
    container.addEventListener(
      "click",
      event => {
        if (!(event.target instanceof Element)) {
          return;
        }

        const image = event.target.closest(
          ".gslide.current .gslide-media img"
        );

        if (!image || image !== getActiveImage(container)) {
          return;
        }

        event.preventDefault();
        event.stopPropagation();
        event.stopImmediatePropagation();

        const state = getState(container);

        if (!state) {
          return;
        }

        /*
         * Um clique gerado ao final de um arraste não deve
         * retirar o zoom.
         */
        if (state.suppressClick) {
          state.suppressClick = false;
          return;
        }

        toggleZoom(state);
      },
      true
    );
  }

  function installWheelZoom(container) {
    container.addEventListener(
      "wheel",
      event => {
        if (window.innerWidth <= 768) {
          return;
        }

        const state = getState(container);

        if (!state) {
          return;
        }

        event.preventDefault();
        event.stopPropagation();
        event.stopImmediatePropagation();

        if (!activateZoomContext(state)) {
          return;
        }

        const mediaRect =
          state.media.getBoundingClientRect();

        const anchor = {
          x:
            event.clientX -
            (mediaRect.left + mediaRect.width / 2),
          y:
            event.clientY -
            (mediaRect.top + mediaRect.height / 2)
        };

        const factor = Math.exp(
          -event.deltaY * WHEEL_SENSITIVITY
        );

        setScale(
          state,
          state.scale * factor,
          anchor,
          false
        );
      },
      {
        capture: true,
        passive: false
      }
    );
  }

  function installPan(container) {
    container.addEventListener(
      "pointerdown",
      event => {
        if (!(event.target instanceof Element)) {
          return;
        }

        const image = event.target.closest(
          ".gslide.current .gslide-media img"
        );

        if (!image || image !== getActiveImage(container)) {
          return;
        }

        const state = getState(container);

        if (
          !state ||
          state.scale <= MIN_SCALE + 0.001
        ) {
          return;
        }

        event.preventDefault();
        event.stopPropagation();
        event.stopImmediatePropagation();

        state.dragging = true;
        state.moved = false;
        state.suppressClick = false;
        state.pointerId = event.pointerId;

        state.dragStartX = event.clientX;
        state.dragStartY = event.clientY;

        state.initialX = state.x;
        state.initialY = state.y;

        image.setPointerCapture?.(event.pointerId);
        applyTransform(state, false);
      },
      true
    );

    container.addEventListener(
      "pointermove",
      event => {
        const state = getState(container);

        if (
          !state ||
          !state.dragging ||
          state.pointerId !== event.pointerId
        ) {
          return;
        }

        event.preventDefault();
        event.stopPropagation();
        event.stopImmediatePropagation();

        const deltaX =
          event.clientX - state.dragStartX;

        const deltaY =
          event.clientY - state.dragStartY;

        if (
          Math.abs(deltaX) > 3 ||
          Math.abs(deltaY) > 3
        ) {
          state.moved = true;
        }

        state.x = state.initialX + deltaX;
        state.y = state.initialY + deltaY;

        applyTransform(state, false);
      },
      true
    );

    const finishPan = event => {
      const state = getState(container);

      if (
        !state ||
        !state.dragging ||
        state.pointerId !== event.pointerId
      ) {
        return;
      }

      event.preventDefault();
      event.stopPropagation();
      event.stopImmediatePropagation();

      state.dragging = false;
      state.suppressClick = state.moved;

      state.image.releasePointerCapture?.(
        event.pointerId
      );

      state.pointerId = null;
      applyTransform(state, false);
    };

    container.addEventListener(
      "pointerup",
      finishPan,
      true
    );

    container.addEventListener(
      "pointercancel",
      finishPan,
      true
    );
  }

  function installOutsideClose(container) {
  container.addEventListener(
    "click",
    event => {
      if (!(event.target instanceof Element)) {
        return;
      }

      const state = getState(container);

      if (
        !state ||
        !state.slide.classList.contains(
          "custom-zoom-context"
        )
      ) {
        return;
      }

      /*
       * Cliques na imagem continuam controlando o zoom.
       * Cliques nos botões continuam com suas funções normais.
       */
      if (
        event.target.closest(
          ".gslide-media img, " +
          ".gbtn, " +
          ".gclose, " +
          ".gnext, " +
          ".gprev, " +
          ".gslide-description"
        )
      ) {
        return;
      }

      /*
       * A região preta pertence ao contêiner de mídia quando
       * nosso contexto de zoom está ativo. Simulamos o fechamento
       * pelo controle oficial do próprio GLightbox.
       */
      const closeButton =
        container.querySelector(".gclose");

      if (!closeButton) {
        return;
      }

      event.preventDefault();
      event.stopPropagation();
      event.stopImmediatePropagation();

      closeButton.click();
    },
    true
  );
}

  function install(container) {
    if (
      container.dataset.customZoomInstalled === "true"
    ) {
      resetInactiveSlides(container);
      syncButton(container);
      return;
    }

    const button = createButton(container);

    if (!button) {
      return;
    }

    container.dataset.customZoomInstalled = "true";

    installImageClick(container);
    installWheelZoom(container);
    installPan(container);
    installOutsideClose(container);

    const observer = new MutationObserver(() => {
      resetInactiveSlides(container);
      syncButton(container);
    });

    observer.observe(container, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ["class", "style"]
    });

    syncButton(container);
  }

  function scan() {
    document
      .querySelectorAll(CONTAINER_SELECTOR)
      .forEach(install);
  }

  const pageObserver = new MutationObserver(scan);

  pageObserver.observe(document.documentElement, {
    childList: true,
    subtree: true
  });

  window.addEventListener("resize", () => {
    document
      .querySelectorAll(CONTAINER_SELECTOR)
      .forEach(container => {
        const state = getState(container);

        /*
         * O redimensionamento altera os limites de movimento.
         * Restaurar para 1× evita coordenadas inválidas.
         */
        if (state) {
          setScale(state, MIN_SCALE, null, false);
        }

        syncButton(container);
      });
  });

  document.addEventListener("DOMContentLoaded", scan);
  window.addEventListener("load", scan);

  scan();
})();
