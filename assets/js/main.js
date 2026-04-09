(() => {
  const COPY_ICON_SVG =
    '<svg class="code-copy-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="M8 4h10a2 2 0 0 1 2 2v12h-2V6H8V4zm-3 4h10a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V10a2 2 0 0 1 2-2zm0 2v10h10V10H5z"/></svg>';

  const onReady = (handler) => {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", handler, { once: true });
      return;
    }
    handler();
  };

  const normalize = (value) =>
    String(value || "")
      .toLowerCase()
      .replace(/\s+/g, " ")
      .trim();

  const splitKeywords = (value) => normalize(value).split(" ").filter(Boolean);

  const copyText = async (text) => {
    if (!text) return false;

    if (navigator.clipboard && window.isSecureContext) {
      try {
        await navigator.clipboard.writeText(text);
        return true;
      } catch (_error) {
        // Fall back to execCommand below.
      }
    }

    const textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.setAttribute("readonly", "readonly");
    textarea.style.position = "fixed";
    textarea.style.top = "-9999px";
    document.body.appendChild(textarea);
    textarea.select();

    let copied = false;
    try {
      copied = document.execCommand("copy");
    } catch (_error) {
      copied = false;
    }

    document.body.removeChild(textarea);
    return copied;
  };

  const initSearch = () => {
    const input = document.querySelector("[data-search-input]");
    const resultList = document.querySelector("[data-search-results]");
    const stats = document.querySelector("[data-search-stats]");
    const dataNode = document.getElementById("site-search-data");

    if (!input || !resultList || !stats || !dataNode) return;

    let rawData = [];
    try {
      rawData = JSON.parse(dataNode.textContent || "[]");
    } catch (_error) {
      stats.textContent = "Search index failed to load.";
      return;
    }

    const entries = rawData.map((item, index) => {
      const title = String(item.title || "Untitled");
      const metaFields = [item.platform, item.os, item.difficulty, item.track]
        .map((v) => String(v || "").trim())
        .filter(Boolean);

      return {
        id: index,
        type: String(item.type || "post"),
        title,
        url: String(item.url || "#"),
        date: String(item.date || ""),
        metaFields,
        titleIndex: normalize(title),
        metaIndex: normalize(metaFields.join(" ")),
        bodyIndex: normalize(item.text || ""),
      };
    });

    const formatMeta = (entry) => {
      const chunks = [entry.type === "note" ? "NOTE" : "POST"];

      if (entry.date) chunks.push(entry.date);
      if (entry.metaFields.length) chunks.push(entry.metaFields.join(" / "));

      return chunks.join(" | ");
    };

    const render = (items, query) => {
      resultList.innerHTML = "";

      if (!query) {
        stats.textContent = "Type to search posts and notes.";
        return;
      }

      if (!items.length) {
        stats.textContent = "No results.";
        return;
      }

      stats.textContent = `${items.length} result${items.length > 1 ? "s" : ""}.`;

      const fragment = document.createDocumentFragment();
      items.forEach((entry) => {
        const li = document.createElement("li");
        li.className = "search-result-item";

        const link = document.createElement("a");
        link.className = "search-result-title";
        link.href = entry.url;
        link.textContent = entry.title;

        const meta = document.createElement("p");
        meta.className = "search-result-meta";
        meta.textContent = formatMeta(entry);

        li.appendChild(link);
        li.appendChild(meta);
        fragment.appendChild(li);
      });

      resultList.appendChild(fragment);
    };

    const runSearch = () => {
      const query = input.value;
      const keywords = splitKeywords(query);

      if (!keywords.length) {
        render([], "");
        return;
      }

      const phrase = normalize(query);

      const scored = entries
        .filter((entry) => {
          const haystack = `${entry.titleIndex} ${entry.metaIndex} ${entry.bodyIndex}`;
          return keywords.every((token) => haystack.includes(token));
        })
        .map((entry) => {
          let score = 0;
          keywords.forEach((token) => {
            if (entry.titleIndex.includes(token)) score += 10;
            if (entry.metaIndex.includes(token)) score += 4;
            if (entry.bodyIndex.includes(token)) score += 1;
          });
          if (phrase && entry.titleIndex.includes(phrase)) score += 8;

          return { ...entry, score };
        })
        .sort((a, b) => {
          if (b.score !== a.score) return b.score - a.score;
          return b.date.localeCompare(a.date);
        });

      render(scored, query);
    };

    const url = new URL(window.location.href);
    const initialQ = url.searchParams.get("q") || "";
    if (initialQ) {
      input.value = initialQ;
    }

    input.addEventListener("input", () => {
      const next = input.value.trim();
      const nextUrl = new URL(window.location.href);
      if (next) {
        nextUrl.searchParams.set("q", next);
      } else {
        nextUrl.searchParams.delete("q");
      }
      window.history.replaceState({}, "", nextUrl);
      runSearch();
    });

    runSearch();
  };

  const initToc = () => {
    const tocBox = document.querySelector(".js-toc");
    const tocList = tocBox ? tocBox.querySelector(".toc-list") : null;
    const content = document.querySelector(".post-content");
    const layout = tocBox ? tocBox.closest(".post-float-layout") : null;

    if (!tocBox || !tocList || !content) return;

    const allHeadings = Array.from(content.querySelectorAll("h1, h2, h3, h4"));
    if (!allHeadings.length) {
      tocBox.hidden = true;
      if (layout) layout.classList.remove("has-toc");
      return;
    }

    const levels = Array.from(
      new Set(
        allHeadings
          .map((heading) => Number(heading.tagName.replace("H", "")))
          .filter((level) => Number.isFinite(level))
      )
    ).sort((a, b) => a - b);

    const primaryLevel = levels[0];
    const secondaryLevel = levels[1] || null;
    const headings = allHeadings.filter((heading) => {
      const level = Number(heading.tagName.replace("H", ""));
      return level === primaryLevel || (secondaryLevel && level === secondaryLevel);
    });

    if (!headings.length) {
      tocBox.hidden = true;
      if (layout) layout.classList.remove("has-toc");
      return;
    }

    const usedIds = new Set(
      headings
        .map((h) => String(h.id || "").trim())
        .filter(Boolean)
    );

    const slugify = (text) => {
      const slug = String(text || "")
        .toLowerCase()
        .trim()
        .replace(/[^\w\u4e00-\u9fff\s-]/g, "")
        .replace(/\s+/g, "-")
        .replace(/-+/g, "-");

      return slug || "section";
    };

    const makeUniqueId = (base) => {
      let candidate = base;
      let index = 2;
      while (usedIds.has(candidate) || document.getElementById(candidate)) {
        candidate = `${base}-${index}`;
        index += 1;
      }
      usedIds.add(candidate);
      return candidate;
    };

    const linkMap = new Map();
    const fragment = document.createDocumentFragment();
    let currentPrimaryItem = null;
    let currentPrimaryId = "";

    headings.forEach((heading, idx) => {
      if (!heading.id) {
        const base = slugify(heading.textContent) || `section-${idx + 1}`;
        heading.id = makeUniqueId(base);
      }

      const level = Number(heading.tagName.replace("H", ""));
      const isPrimary = level === primaryLevel || !secondaryLevel;
      const li = document.createElement("li");
      li.className = `toc-item ${isPrimary ? "toc-level-1" : "toc-level-2"}`;

      const link = document.createElement("a");
      link.href = `#${heading.id}`;
      link.textContent = heading.textContent || `Section ${idx + 1}`;

      li.appendChild(link);

      if (isPrimary || !currentPrimaryItem) {
        fragment.appendChild(li);
        currentPrimaryItem = li;
        currentPrimaryId = heading.id;
      } else {
        let sublist = currentPrimaryItem.querySelector(".toc-sublist");
        if (!sublist) {
          sublist = document.createElement("ul");
          sublist.className = "toc-sublist";
          currentPrimaryItem.appendChild(sublist);
        }
        sublist.appendChild(li);
        link.dataset.parentId = currentPrimaryId;
      }

      linkMap.set(heading.id, link);
    });

    tocList.innerHTML = "";
    tocList.appendChild(fragment);
    tocBox.hidden = false;
    if (layout) layout.classList.add("has-toc");

    const setActive = (activeId) => {
      linkMap.forEach((link) => link.classList.remove("active", "active-parent"));

      const activeLink = linkMap.get(activeId);
      if (!activeLink) return;

      activeLink.classList.add("active");
      const parentId = activeLink.dataset.parentId;
      if (parentId) {
        const parentLink = linkMap.get(parentId);
        if (parentLink) parentLink.classList.add("active-parent");
      }
    };

    const updateActiveByScroll = () => {
      const marker = window.innerHeight * 0.24;
      let currentHeading = headings[0];

      headings.forEach((heading) => {
        if (heading.getBoundingClientRect().top <= marker) {
          currentHeading = heading;
        }
      });

      if (currentHeading) setActive(currentHeading.id);
    };

    let scheduled = false;
    const requestUpdate = () => {
      if (scheduled) return;
      scheduled = true;
      window.requestAnimationFrame(() => {
        updateActiveByScroll();
        scheduled = false;
      });
    };

    document.addEventListener("scroll", requestUpdate, { passive: true });
    window.addEventListener("resize", requestUpdate);
    requestUpdate();
  };

  const initCodeCopy = () => {
    const blocks = document.querySelectorAll(".post-content pre");
    if (!blocks.length) return;

    blocks.forEach((pre) => {
      if (pre.querySelector(".code-copy-btn")) return;

      const source = pre.querySelector("code") || pre;
      const value = (source.innerText || source.textContent || "").trim();
      if (!value) return;

      const button = document.createElement("button");
      button.type = "button";
      button.className = "code-copy-btn";
      button.innerHTML = COPY_ICON_SVG;
      button.setAttribute("aria-label", "Copy code to clipboard");
      button.setAttribute("title", "Copy");

      let timerId;
      button.addEventListener("click", async () => {
        const raw = (source.innerText || source.textContent || "").replace(/\n$/, "");
        const ok = await copyText(raw);

        button.classList.toggle("is-success", ok);
        button.classList.toggle("is-failed", !ok);
        button.setAttribute("title", ok ? "Copied" : "Copy failed");

        window.clearTimeout(timerId);
        timerId = window.setTimeout(() => {
          button.classList.remove("is-success", "is-failed");
          button.setAttribute("title", "Copy");
        }, 1400);
      });

      pre.appendChild(button);
    });
  };

  const initImageUx = () => {
    const content = document.querySelector(".post-content");
    if (!content) return;

    const images = Array.from(content.querySelectorAll("img"));
    if (!images.length) return;

    let lightbox;
    let lightboxImg;
    let lightboxCaption;

    const closeLightbox = () => {
      if (!lightbox) return;
      lightbox.classList.remove("is-open");
      lightbox.setAttribute("aria-hidden", "true");
      document.body.classList.remove("img-lightbox-open");
      if (lightboxImg) lightboxImg.src = "";
      if (lightboxCaption) lightboxCaption.textContent = "";
    };

    const ensureLightbox = () => {
      if (lightbox) return;

      lightbox = document.createElement("div");
      lightbox.className = "img-lightbox";
      lightbox.setAttribute("aria-hidden", "true");

      const closeBtn = document.createElement("button");
      closeBtn.type = "button";
      closeBtn.className = "img-lightbox-close";
      closeBtn.textContent = "Close";
      closeBtn.setAttribute("aria-label", "Close image preview");

      lightboxImg = document.createElement("img");
      lightboxImg.className = "img-lightbox-content";
      lightboxImg.alt = "Image preview";

      lightboxCaption = document.createElement("p");
      lightboxCaption.className = "img-lightbox-caption";

      closeBtn.addEventListener("click", closeLightbox);
      lightbox.addEventListener("click", (event) => {
        if (event.target === lightbox) closeLightbox();
      });

      document.addEventListener("keydown", (event) => {
        if (event.key === "Escape") closeLightbox();
      });

      lightbox.appendChild(closeBtn);
      lightbox.appendChild(lightboxImg);
      lightbox.appendChild(lightboxCaption);
      document.body.appendChild(lightbox);
    };

    const openLightbox = (img) => {
      ensureLightbox();
      lightboxImg.src = img.currentSrc || img.src;
      lightboxImg.alt = img.alt || "Image preview";
      lightboxCaption.textContent = img.alt || "";
      lightbox.classList.add("is-open");
      lightbox.setAttribute("aria-hidden", "false");
      document.body.classList.add("img-lightbox-open");
    };

    images.forEach((img) => {
      if (!img.getAttribute("loading")) img.setAttribute("loading", "lazy");
      if (!img.getAttribute("decoding")) img.setAttribute("decoding", "async");
      img.classList.add("zoomable-image");

      img.addEventListener("click", (event) => {
        event.preventDefault();
        openLightbox(img);
      });
    });
  };

  const initPixelPet = () => {
    const widget = document.querySelector("[data-pet-widget]");
    const sprite = document.querySelector("[data-pet-sprite]");
    const bodyBtn = document.querySelector("[data-pet-body]");
    const bubble = document.querySelector("[data-pet-bubble]");
    const textNode = document.querySelector("[data-pet-text]");
    const closeBtn = document.querySelector("[data-pet-close]");

    if (!widget || !sprite || !bodyBtn || !bubble || !textNode) return;

    const prefersReducedMotion =
      window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (prefersReducedMotion) widget.classList.add("reduced-motion");

    const frameA = sprite.dataset.frameA || sprite.getAttribute("src") || "";
    const frameB = sprite.dataset.frameB || frameA;
    let useBFrame = false;

    if (!prefersReducedMotion && frameA && frameB && frameA !== frameB) {
      window.setInterval(() => {
        useBFrame = !useBFrame;
        sprite.src = useBFrame ? frameB : frameA;
      }, 820);
    }

    const chatter = [
      "今天先信息收集，别急着提权。",
      "你再点我一次，我就给你 root luck。",
      "记得保存截图，复盘最怕缺证据。",
      "看到奇怪端口先做服务识别。",
      "小提示：失败不是卡住，是在收集线索。",
      "你负责思路，我负责卖萌。",
    ];

    const pageHint = (() => {
      const path = window.location.pathname || "/";
      if (path === "/" || path === "") return "欢迎回来，今天想复盘哪一台？";
      if (path.startsWith("/notes/") && path !== "/notes/") return "这篇不错，往下翻我帮你盯目录。";
      if (path.startsWith("/search/")) return "试试搜平台和难度组合，比如：HTB Windows Hard。";
      if (path.startsWith("/notes/")) return "选一台机器开练吧，我在右下角加油。";
      return "摸摸头，继续推进。";
    })();

    const pick = (items) => items[Math.floor(Math.random() * items.length)];
    let hideTimerId = 0;

    const hideBubble = () => {
      bubble.hidden = true;
      widget.classList.remove("is-chatting");
    };

    const showMessage = (message, duration = 3200) => {
      textNode.textContent = message;
      bubble.hidden = false;
      widget.classList.add("is-chatting");
      window.clearTimeout(hideTimerId);
      if (duration > 0) {
        hideTimerId = window.setTimeout(hideBubble, duration);
      }
    };

    bodyBtn.addEventListener("click", () => {
      widget.classList.remove("is-hop");
      void widget.offsetWidth;
      widget.classList.add("is-hop");
      showMessage(pick(chatter));
    });

    bodyBtn.addEventListener("mouseenter", () => {
      if (!bubble.hidden) return;
      if (Math.random() < 0.22) showMessage(pick(chatter), 2200);
    });

    if (closeBtn) {
      closeBtn.addEventListener("click", (event) => {
        event.stopPropagation();
        hideBubble();
      });
    }

    bubble.addEventListener("click", (event) => {
      event.stopPropagation();
    });

    window.setTimeout(() => {
      showMessage(pageHint, 3600);
    }, 900);

    window.setInterval(() => {
      if (document.hidden || !bubble.hidden) return;
      if (Math.random() < 0.48) showMessage(pick(chatter), 2800);
    }, 22000);
  };

  onReady(() => {
    initSearch();
    initToc();
    initCodeCopy();
    initImageUx();
    initPixelPet();
  });
})();
