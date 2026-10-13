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

    const previousFocus = document.activeElement;
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
    if (previousFocus && previousFocus.focus) previousFocus.focus();
    return copied;
  };

  const updateQuery = (values) => {
    const url = new URL(window.location.href);
    Object.entries(values).forEach(([key, value]) => {
      if (value) url.searchParams.set(key, value);
      else url.searchParams.delete(key);
    });
    window.history.replaceState({}, "", url);
  };

  const initSearch = () => {
    const shell = document.querySelector("[data-search-index]");
    if (!shell) return;
    const input = shell.querySelector("[data-search-input]");
    const type = shell.querySelector("[data-search-type]");
    const form = shell.querySelector("form");
    const results = shell.querySelector("[data-search-results]");
    const stats = shell.querySelector("[data-search-stats]");
    const retry = shell.querySelector("[data-search-retry]");
    let entries = null;
    let timer;

    const highlight = (node, value, keywords) => {
      // Construct text nodes rather than interpreting index/query text as HTML.
      const lower = value.toLowerCase();
      let position = 0;
      while (position < value.length) {
        let next = -1;
        let length = 0;
        keywords.forEach((keyword) => {
          const match = lower.indexOf(keyword, position);
          if (match >= 0 && (next < 0 || match < next || (match === next && keyword.length > length))) {
            next = match;
            length = keyword.length;
          }
        });
        if (next < 0) { node.append(value.slice(position)); break; }
        node.append(value.slice(position, next));
        const mark = document.createElement("mark");
        mark.textContent = value.slice(next, next + length);
        node.append(mark);
        position = next + length;
      }
    };

    const runSearch = () => {
      if (!entries) return;
      const keywords = splitKeywords(input.value);
      results.replaceChildren();
      if (!keywords.length && !type.value) {
        stats.textContent = `已收录 ${entries.length} 篇内容。输入关键词开始搜索。`;
        return;
      }
      const matches = entries.filter((entry) =>
        (!type.value || entry.type === type.value) && keywords.every((word) => entry.index.includes(word))
      ).map((entry) => ({
        ...entry,
        score: keywords.reduce((total, word) => total +
          (entry.titleIndex.includes(word) ? 10 : 0) + (entry.metaIndex.includes(word) ? 4 : 0), 0),
      })).sort((a, b) => b.score - a.score || b.date.localeCompare(a.date) || a.title.localeCompare(b.title, "zh-CN"));
      stats.textContent = matches.length ? `找到 ${matches.length} 篇相关内容。` : "没有找到相关内容。试试更短的关键词，或切换内容类型。";
      const fragment = document.createDocumentFragment();
      matches.forEach((entry) => {
        const li = document.createElement("li");
        li.className = "search-result-item nes-container is-dark";
        const link = document.createElement("a");
        link.className = "search-result-title";
        link.href = entry.url;
        highlight(link, entry.title, keywords);
        const meta = document.createElement("p");
        meta.className = "search-result-meta";
        meta.textContent = [entry.type === "note" ? "靶机笔记" : "技术文章", entry.date, ...entry.meta].filter(Boolean).join(" · ");
        const snippet = document.createElement("p");
        snippet.className = "search-result-snippet";
        const offsets = keywords.map((word) => entry.text.toLowerCase().indexOf(word)).filter((n) => n >= 0);
        const start = Math.max(0, (offsets.length ? Math.min(...offsets) : 0) - 55);
        const excerpt = (start ? "…" : "") + entry.text.slice(start, start + 200) + (entry.text.length > start + 200 ? "…" : "");
        highlight(snippet, excerpt, keywords);
        li.append(link, meta, snippet);
        fragment.append(li);
      });
      results.append(fragment);
    };
    const restore = () => {
      const params = new URL(window.location.href).searchParams;
      input.value = params.get("q") || "";
      type.value = ["note", "post"].includes(params.get("type")) ? params.get("type") : "";
      runSearch();
    };
    const change = () => {
      window.clearTimeout(timer);
      updateQuery({ q: input.value.trim(), type: type.value });
      runSearch();
    };
    input.addEventListener("input", () => {
      window.clearTimeout(timer);
      timer = window.setTimeout(change, 120);
    });
    type.addEventListener("change", change);
    form.addEventListener("submit", (event) => { event.preventDefault(); change(); });
    form.addEventListener("reset", (event) => {
      event.preventDefault(); input.value = ""; type.value = ""; change(); input.focus();
    });
    window.addEventListener("popstate", () => { window.clearTimeout(timer); restore(); });
    const loadIndex = async () => {
      retry.hidden = true;
      stats.textContent = "正在加载搜索索引…";
      const controller = new AbortController();
      const timeout = window.setTimeout(() => controller.abort(), 15000);
      try {
        const response = await fetch(shell.dataset.searchIndex, { signal: controller.signal });
        if (!response.ok) throw new Error("Index unavailable");
        const data = await response.json();
        if (!Array.isArray(data)) throw new Error("Invalid index");
        const decoder = document.createElement("textarea");
        entries = data.map((item) => {
          if (!item || typeof item.title !== "string" || typeof item.url !== "string") throw new Error("Invalid entry");
          const url = new URL(item.url, window.location.href);
          if (url.origin !== window.location.origin || !["http:", "https:"].includes(url.protocol)) throw new Error("Invalid entry URL");
          decoder.innerHTML = String(item.text || "");
          const text = decoder.value.replace(/\s+/g, " ").trim();
          const meta = [item.platform, item.os, item.difficulty, item.track, item.status, ...(item.tags || [])].filter(Boolean);
          return { ...item, url: url.href, date: item.date || "", text, meta,
            titleIndex: normalize(item.title), metaIndex: normalize(meta.join(" ")),
            index: normalize([item.title, ...meta, text].join(" ")) };
        });
        runSearch();
      } catch (_error) {
        entries = null;
        stats.textContent = "搜索索引加载失败，请检查网络后重试。也可以从导航浏览笔记和分类。";
        retry.hidden = false;
      } finally { window.clearTimeout(timeout); }
    };
    retry.addEventListener("click", loadIndex);
    restore();
    loadIndex();
  };

  const initNoteFilters = () => {
    const browser = document.querySelector("[data-note-browser]");
    if (!browser) return;
    const form = browser.querySelector("[data-note-filters]");
    const cards = Array.from(browser.querySelectorAll("[data-note-card]"));
    const count = browser.querySelector("[data-note-count]");
    const empty = browser.querySelector("[data-note-empty]");
    const fields = ["platform", "os", "difficulty", "track", "status"];
    const difficultyOrder = ["Easy", "Medium", "Hard", "Insane", "Unknown"];
    fields.forEach((field) => {
      const values = Array.from(new Set(cards.map((card) => card.dataset[field])));
      values.sort((a, b) => field === "difficulty" ?
        (difficultyOrder.indexOf(a) < 0 ? 99 : difficultyOrder.indexOf(a)) - (difficultyOrder.indexOf(b) < 0 ? 99 : difficultyOrder.indexOf(b)) : a.localeCompare(b));
      values.forEach((value) => {
        const option = document.createElement("option");
        option.value = value;
        option.textContent = `${value} (${cards.filter((card) => card.dataset[field] === value).length})`;
        form.elements[field].append(option);
      });
    });
    const render = () => {
      const keywords = splitKeywords(form.elements.q.value);
      let visible = 0;
      cards.forEach((card) => {
        const matches = keywords.every((word) => normalize(card.dataset.title).includes(word)) &&
          fields.every((field) => !form.elements[field].value || card.dataset[field] === form.elements[field].value);
        card.hidden = !matches;
        if (matches) visible += 1;
      });
      count.textContent = `显示 ${visible} / ${cards.length} 篇笔记`;
      empty.hidden = visible > 0;
    };
    const restore = () => {
      const params = new URL(window.location.href).searchParams;
      form.elements.q.value = params.get("q") || "";
      fields.forEach((field) => {
        const requested = params.get(field) || "";
        const select = form.elements[field];
        select.value = Array.from(select.options).some((option) => option.value === requested) ? requested : "";
      });
      render();
    };
    const change = () => {
      updateQuery(Object.fromEntries([...fields, "q"].map((field) => [field, form.elements[field].value.trim()])));
      render();
    };
    form.addEventListener("input", change);
    form.addEventListener("change", change);
    form.addEventListener("submit", (event) => { event.preventDefault(); change(); });
    form.addEventListener("reset", (event) => {
      event.preventDefault();
      [...fields, "q"].forEach((field) => { form.elements[field].value = ""; });
      change();
    });
    window.addEventListener("popstate", restore);
    form.hidden = false;
    restore();
  };

  const initToc = () => {
    const toc = document.querySelector(".js-toc");
    const content = document.querySelector(".post-content");
    if (!toc || !content) return;
    const headings = Array.from(content.querySelectorAll("h1, h2, h3, h4"));
    if (!headings.length) return;
    const list = toc.querySelector(".toc-list");
    const minimum = Math.min(...headings.map((heading) => Number(heading.tagName.slice(1))));
    const links = new Map();
    headings.forEach((heading, index) => {
      if (!heading.id) {
        let id = `section-${index + 1}`;
        while (document.getElementById(id)) id += "-section";
        heading.id = id;
      }
      const item = document.createElement("li");
      item.className = "toc-item";
      item.style.setProperty("--toc-depth", Number(heading.tagName.slice(1)) - minimum);
      const link = document.createElement("a");
      link.href = `#${encodeURIComponent(heading.id)}`;
      link.textContent = heading.textContent;
      item.append(link); list.append(item); links.set(heading, link);
    });
    toc.hidden = false;
    toc.closest(".post-float-layout").classList.add("has-toc");
    const desktop = window.matchMedia("(min-width: 981px)");
    const setLayout = () => { toc.open = desktop.matches; };
    setLayout();
    desktop.addEventListener("change", setLayout);
    const update = () => {
      let current = headings[0];
      for (const heading of headings) {
        if (heading.getBoundingClientRect().top <= 150) current = heading;
      }
      links.forEach((link, heading) => {
        const active = heading === current;
        link.classList.toggle("active", active);
        if (active) link.setAttribute("aria-current", "location");
        else link.removeAttribute("aria-current");
      });
    };
    let scheduled = false;
    const requestUpdate = () => {
      if (scheduled) return;
      scheduled = true;
      window.requestAnimationFrame(() => { update(); scheduled = false; });
    };
    document.addEventListener("scroll", requestUpdate, { passive: true });
    window.addEventListener("resize", requestUpdate);
    requestUpdate();
  };

  const initCodeCopy = () => {
    const blocks = document.querySelectorAll(".post-content pre");
    if (!blocks.length) return;

    blocks.forEach((pre) => {
      if (pre.closest(".code-block")) return;

      const source = pre.querySelector("code") || pre;
      const value = (source.innerText || source.textContent || "").trim();
      if (!value) return;

      const button = document.createElement("button");
      button.type = "button";
      button.className = "code-copy-btn";
      button.innerHTML = COPY_ICON_SVG;
      button.setAttribute("aria-label", "复制代码");
      button.setAttribute("title", "复制代码");

      const wrapper = document.createElement("div");
      wrapper.className = "code-block";
      pre.before(wrapper);
      wrapper.append(pre);
      pre.tabIndex = 0;
      const status = document.createElement("span");
      status.className = "sr-only";
      status.setAttribute("role", "status");
      wrapper.append(status);
      let timerId;
      button.addEventListener("click", async () => {
        const raw = (source.textContent || "").replace(/\n$/, "");
        const ok = await copyText(raw);

        button.classList.toggle("is-success", ok);
        button.classList.toggle("is-failed", !ok);
        button.setAttribute("title", ok ? "已复制" : "复制失败，请手动选择代码");
        status.textContent = ok ? "代码已复制" : "复制失败，请手动选择代码";

        window.clearTimeout(timerId);
        timerId = window.setTimeout(() => {
          button.classList.remove("is-success", "is-failed");
          status.textContent = "";
          button.setAttribute("title", "复制代码");
        }, 1400);
      });

      wrapper.appendChild(button);
    });
  };

  const initImageUx = () => {
    const images = document.querySelectorAll(".post-content img");
    let dialog;
    let preview;
    let caption;
    const open = (image) => {
      if (!dialog) {
        dialog = document.createElement("dialog");
        dialog.className = "img-lightbox";
        dialog.setAttribute("aria-label", "图片预览");
        const close = document.createElement("button");
        close.type = "button";
        close.className = "img-lightbox-close";
        close.textContent = "关闭 ✕";
        close.autofocus = true;
        close.addEventListener("click", () => dialog.close());
        preview = document.createElement("img");
        preview.className = "img-lightbox-content";
        caption = document.createElement("p");
        caption.className = "img-lightbox-caption";
        dialog.append(close, preview, caption);
        dialog.addEventListener("click", (event) => { if (event.target === dialog) dialog.close(); });
        dialog.addEventListener("close", () => {
          document.body.classList.remove("img-lightbox-open");
          preview.removeAttribute("src");
        });
        document.body.append(dialog);
      }
      preview.src = image.currentSrc || image.src;
      preview.alt = image.alt || "笔记截图";
      caption.textContent = image.alt || "按 Esc 或点击关闭返回阅读";
      dialog.showModal();
      document.body.classList.add("img-lightbox-open");
    };
    images.forEach((image) => {
      image.loading = "lazy";
      image.decoding = "async";
      // Preserve an author's explicit image link, rather than swallowing it.
      if (!image.closest("a") && typeof HTMLDialogElement !== "undefined" && HTMLDialogElement.prototype.showModal) {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "image-zoom-button";
        button.setAttribute("aria-label", `放大图片：${image.alt || "笔记截图"}`);
        image.before(button); button.append(image);
        button.addEventListener("click", () => open(image));
      }
      const onError = () => {
        if (image.dataset.failed) return;
        image.dataset.failed = "true";
        const message = document.createElement("span");
        message.className = "image-error";
        message.textContent = `图片加载失败：${image.alt || "笔记截图"}`;
        image.after(message);
        if (image.parentElement.classList.contains("image-zoom-button")) image.parentElement.disabled = true;
      };
      image.addEventListener("error", onError, { once: true });
      if (image.complete && image.naturalWidth === 0) onError();
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
      showMessage(Math.random() < 0.3 ? pageHint : pick(chatter));
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


  };

  onReady(() => {
    initSearch();
    initNoteFilters();
    initToc();
    initCodeCopy();
    initImageUx();
    initPixelPet();
  });
})();
