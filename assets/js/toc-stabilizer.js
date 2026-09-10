(() => {
  const TOC_SELECTOR =
    "#toc a.toc-link, #toc-popup-content a.toc-link";

  const CONTENT_SELECTOR = ".content";

  const MAX_STABILIZATION_TIME = 8000;
  const CHECK_INTERVAL = 100;
  const REQUIRED_STABLE_CHECKS = 5;
  const POSITION_TOLERANCE = 2;

  let navigationId = 0;

  function resolveTarget(link) {
    const hash = new URL(link.href, location.href).hash;

    if (!hash) {
      return null;
    }

    let id;

    try {
      id = decodeURIComponent(hash.slice(1));
    } catch {
      id = hash.slice(1);
    }

    const target = document.getElementById(id);

    if (!target) {
      return null;
    }

    return {
      hash,
      target
    };
  }

  function getScrollMargin(target) {
    return (
      parseFloat(
        getComputedStyle(target).scrollMarginTop
      ) || 0
    );
  }

  function getTargetDifference(target) {
    return (
      target.getBoundingClientRect().top -
      getScrollMargin(target)
    );
  }

  function correctPosition(target) {
    const difference = getTargetDifference(target);

    if (Math.abs(difference) <= POSITION_TOLERANCE) {
      return;
    }

    window.scrollBy({
      top: difference,
      left: 0,
      behavior: "auto"
    });
  }

  function getImagesBeforeTarget(target) {
    const content = document.querySelector(CONTENT_SELECTOR);

    if (!content) {
      return [];
    }

    return [...content.querySelectorAll("img")].filter(image => {
      return Boolean(
        image.compareDocumentPosition(target) &
          Node.DOCUMENT_POSITION_FOLLOWING
      );
    });
  }

  function prepareImages(images, target, currentNavigation) {
    const correctIfCurrent = () => {
      if (currentNavigation !== navigationId) {
        return;
      }

      requestAnimationFrame(() => {
        correctPosition(target);
      });
    };

    for (const image of images) {
      /*
       * Só altera o carregamento durante a navegação.
       * Não exige width ou height no Markdown.
       */
      image.loading = "eager";

      if ("fetchPriority" in image) {
        image.fetchPriority = "high";
      }

      if (!image.complete) {
        image.addEventListener(
          "load",
          correctIfCurrent,
          { once: true }
        );

        image.addEventListener(
          "error",
          correctIfCurrent,
          { once: true }
        );
      }
    }
  }

  function allImagesFinished(images) {
    return images.every(image => image.complete);
  }

  function stabilize(
    target,
    images,
    currentNavigation
  ) {
    const startedAt = performance.now();

    let previousAbsolutePosition = null;
    let stableChecks = 0;

    const check = () => {
      if (currentNavigation !== navigationId) {
        return;
      }

      const absolutePosition =
        window.scrollY +
        target.getBoundingClientRect().top;

      const difference = getTargetDifference(target);

      const absolutePositionStable =
        previousAbsolutePosition !== null &&
        Math.abs(
          absolutePosition - previousAbsolutePosition
        ) <= POSITION_TOLERANCE;

      const viewportPositionCorrect =
        Math.abs(difference) <= POSITION_TOLERANCE;

      if (
        absolutePositionStable &&
        viewportPositionCorrect
      ) {
        stableChecks += 1;
      } else {
        stableChecks = 0;
      }

      previousAbsolutePosition = absolutePosition;

      correctPosition(target);

      const imagesFinished =
        allImagesFinished(images);

      const stabilized =
        stableChecks >= REQUIRED_STABLE_CHECKS &&
        imagesFinished;

      const timedOut =
        performance.now() - startedAt >=
        MAX_STABILIZATION_TIME;

      if (!stabilized && !timedOut) {
        window.setTimeout(check, CHECK_INTERVAL);
      }
    };

    requestAnimationFrame(check);
  }

  document.addEventListener(
    "click",
    event => {
      if (!(event.target instanceof Element)) {
        return;
      }

      const link = event.target.closest(TOC_SELECTOR);

      if (!link) {
        return;
      }

      const destination = resolveTarget(link);

      if (!destination) {
        return;
      }

      /*
       * Não cancela nem substitui o comportamento do Chirpy.
       * Apenas acompanha e corrige o salto existente.
       */
      const currentNavigation = ++navigationId;

      const images = getImagesBeforeTarget(
        destination.target
      );

      prepareImages(
        images,
        destination.target,
        currentNavigation
      );

      const start = () => {
        if (currentNavigation !== navigationId) {
          return;
        }

        correctPosition(destination.target);

        stabilize(
          destination.target,
          images,
          currentNavigation
        );

        /*
         * Fontes podem alterar levemente as quebras de linha.
         */
        document.fonts?.ready.then(() => {
          if (currentNavigation === navigationId) {
            correctPosition(destination.target);
          }
        });
      };

      /*
       * No TOC móvel, espera o popup começar a fechar.
       */
      if (link.closest("#toc-popup-content")) {
        window.setTimeout(start, 300);
      } else {
        window.setTimeout(start, 0);
      }
    },
    true
  );

  /*
   * Se o leitor começar a navegar manualmente, a correção
   * para imediatamente e não disputa a rolagem com ele.
   */
  window.addEventListener(
    "wheel",
    () => {
      navigationId += 1;
    },
    { passive: true }
  );

  window.addEventListener(
    "touchstart",
    () => {
      navigationId += 1;
    },
    { passive: true }
  );

  document.addEventListener("keydown", event => {
    const navigationKeys = [
      "ArrowUp",
      "ArrowDown",
      "PageUp",
      "PageDown",
      "Home",
      "End",
      " "
    ];

    if (navigationKeys.includes(event.key)) {
      navigationId += 1;
    }
  });
})();
