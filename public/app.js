const articleInput = document.querySelector("#markdown");
const wordCount = document.querySelector("#word-count");

if (articleInput && wordCount) {
  const updateCount = () => {
    const words = articleInput.value.trim().split(/\s+/).filter(Boolean).length;
    wordCount.textContent = `${words} ${words === 1 ? "word" : "words"}`;
  };
  articleInput.addEventListener("input", updateCount);
  updateCount();
}

const insertLinkButton = document.querySelector("#insert-link");
const linkTextInput = document.querySelector("#link-text");
const linkUrlInput = document.querySelector("#link-url");
const linkStatus = document.querySelector("#link-status");

if (articleInput && insertLinkButton && linkTextInput && linkUrlInput && linkStatus) {
  insertLinkButton.addEventListener("click", () => {
    const start = articleInput.selectionStart ?? articleInput.value.length;
    const end = articleInput.selectionEnd ?? start;
    const selectedText = articleInput.value.slice(start, end);
    const label = (linkTextInput.value.trim() || selectedText.trim())
      .replace(/[\[\]\r\n]/g, " ").trim().slice(0, 300);
    if (!label) {
      linkStatus.textContent = "Enter link text or select words in the article first.";
      linkTextInput.focus();
      return;
    }

    let destination;
    try {
      destination = new URL(linkUrlInput.value.trim());
      if (!["http:", "https:"].includes(destination.protocol) || destination.username || destination.password) {
        throw new Error("Use a public http:// or https:// address without login credentials.");
      }
    } catch (error) {
      linkStatus.textContent = error.message || "Enter a complete public URL, including https://.";
      linkUrlInput.focus();
      return;
    }
    const href = destination.toString().replace(/\(/g, "%28").replace(/\)/g, "%29");
    const markdownLink = `[${label}](${href})`;
    articleInput.setRangeText(markdownLink, start, end, "end");
    articleInput.dispatchEvent(new Event("input", { bubbles: true }));
    articleInput.focus();
    linkStatus.textContent = "Link added to the article. Publish the note, then email it from Published notes.";
  });
}

const pendingLinkRetry = document.querySelector('[data-auto-retry="true"]');
if (pendingLinkRetry) {
  window.setTimeout(() => window.location.replace(pendingLinkRetry.href), 10_000);
}