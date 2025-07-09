/*!
 * ZapCaptcha – Human-first cryptographic CAPTCHA system
 * -----------------------------------------------------
 * Designed and developed by QVLx Labs.
 * https://www.qvlx.com
 *
 * © 2024–2025 QVLx Labs. All rights reserved.
 * ZapCaptcha is a proprietary CAPTCHA system for front-end validation without backend server reliance.
 *
 * This software is licensed for non-commercial use and authorized commercial use only.
 * Unauthorized reproduction, redistribution, or tampering is strictly prohibited.
 *
 * ZapCaptcha includes anti-bot measures, DOM mutation traps, and telemetry hooks.
 * Attempted bypass, obfuscation, or automation is a violation of applicable laws and terms of use.
 *
 * To license ZapCaptcha for enterprise/commercial use, contact:
 * security@qvlx.com
 */

const preload = document.createElement("link");
preload.rel = "preload";
preload.as = "style";
preload.href = "https://zapcaptcha.com/zapcaptcha.css";
preload.onload = function () {
  this.rel = "stylesheet";
};
document.head.appendChild(preload);

window.addEventListener("DOMContentLoaded", () => {
  const inlineTrigger = document.getElementById("example1_button");
  
  if (inlineTrigger) {
    inlineTrigger.addEventListener("click", (e) => {
      e.preventDefault();
      const result = inlineTrigger.closest(".example-box")?.querySelector(".inline-result");

      window.ZapCaptcha?.verify(inlineTrigger, () => {
        if (result) result.textContent = "✅ Human verified!";
      });
    });
  }
  
  const formTrigger = document.getElementById("example2_button");

  if (formTrigger) {
    formTrigger.addEventListener("click", (e) => {
      e.preventDefault();
      const form = document.getElementById("demoForm");

      window.ZapCaptcha?.verify(formTrigger, () => {
        form.submit();
      });
    });
  }
  
  const inline2Trigger = document.getElementById("example3_button");

  if (inline2Trigger) {
      inline2Trigger.addEventListener("click", (e) => {
        e.preventDefault();
        const result = document.querySelector("#example3_button + .inline-result");
  
        window.ZapCaptcha?.verify(inline2Trigger, () => {
          if (result) result.textContent = "✅ Human verified!";
        });
      });
    }
  
});

document.getElementById("bolt").addEventListener("click", () => {
  const line1 = document.querySelector(".zap-svg .line-1");
  const line2 = document.querySelector(".zap-svg .line-2");

  if (!line1 || !line2) return;

  // Clone the paths to restart animation
  const clone1 = line1.cloneNode(true);
  const clone2 = line2.cloneNode(true);

  line1.replaceWith(clone1);
  line2.replaceWith(clone2);
});

window.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll('.zapcaptcha-button').forEach(button => {
    const restartGleam = () => {
      button.classList.remove('gleaming');
      void button.offsetWidth; // Force reflow
      button.classList.add('gleaming');

      // Schedule next gleam cycle
      setTimeout(restartGleam, 15000); // delay between gleams
    };

    // Initial trigger
    setTimeout(restartGleam, 5300); // optional small delay on first run
  });
});

window.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll('.cta-button').forEach(button => {
    const restartGleam = () => {
      button.classList.remove('gleaming');
      void button.offsetWidth; // Force reflow
      button.classList.add('gleaming');

      // Schedule next gleam cycle
      setTimeout(restartGleam, 15000); // delay between gleams
    };

    // Initial trigger
    setTimeout(restartGleam, 5300); // optional small delay on first run
  });
});

window.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll('.opener').forEach(button => {
    const restartGleam = () => {
      button.classList.remove('gleaming');
      void button.offsetWidth; // Force reflow
      button.classList.add('gleaming');

      // Schedule next gleam cycle
      setTimeout(restartGleam, 15000); // delay between gleams
    };

    // Initial trigger
    setTimeout(restartGleam, 5300); // optional small delay on first run
  });
});
