const textContainer = document.getElementById("animate-text");
const texts = ["UNFORGETTABLE!!", "MEMORABLE!!", "EUPHORIC!"]; // Add your text messages here
let textIndex = 0; // Current text
let charIndex = 0; // Current character
let isErasing = false; // Erasing mode flag

function typeEffect() {
  const currentText = texts[textIndex];
  if (!isErasing) {
    // Typing mode
    textContainer.textContent = currentText.substring(0, charIndex + 1);
    charIndex++;
    if (charIndex === currentText.length) {
      // Switch to erasing after a pause
      isErasing = true;
      setTimeout(typeEffect, 2000);
      return;
    }
  } else {
    // Erasing mode
    textContainer.textContent = currentText.substring(0, charIndex - 1);
    charIndex--;
    if (charIndex === 0) {
      // Switch to next text
      isErasing = false;
      textIndex = (textIndex + 1) % texts.length; // Loop back to the first text
    }
  }
  setTimeout(typeEffect, isErasing ? 50 : 200); // Adjust typing/erasing speed
}

// Start the typing effect
typeEffect();
