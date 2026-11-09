// SPDX-FileCopyrightText: 2026 tokenless contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

// The introduction's "Copy prompt" button copies the prompt shown below
// it. Without JavaScript or a clipboard the button stays hidden, and the
// prompt can still be opened and copied by hand.
(() => {
  for (const button of document.querySelectorAll("button[data-copy-target]")) {
    const source = document.getElementById(button.dataset.copyTarget);
    const label = button.querySelector("span");
    if (!source || !label || !navigator.clipboard) continue;
    const text = label.textContent;
    let reset;
    button.hidden = false;
    button.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(source.textContent.trim());
        label.textContent = "Copied";
      } catch {
        // Show the prompt, so it can be selected instead.
        source.closest("details")?.setAttribute("open", "");
        label.textContent = "Select the prompt below";
      }
      clearTimeout(reset);
      reset = setTimeout(() => (label.textContent = text), 2000);
    });
  }
})();
