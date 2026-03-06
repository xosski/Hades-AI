POC Script — Console - Safe
javascript
Copy
    (() => {
        // Define unique PoC payloads
        const payloads = {
            "No. of Users": "5_POC_TEST_¿_Δ_🔥",
            "default": "POC_INJECTION_¿_Δ_🔥"
        };

        // Grab all input fields inside the form container
        const inputs = document.querySelectorAll('input');

        console.group("POC Field Injection Test");
        inputs.forEach((input, index) => {
            const label = input.getAttribute('aria-label') || input.id || `field_${index}`;

            // Choose a payload based on label or default
            const valueToInject = payloads[label] || payloads["default"];

            // Set the value
            input.value = valueToInject;

            // Trigger change/input events so page scripts register it
            input.dispatchEvent(new Event('input', { bubbles: true }));
            input.dispatchEvent(new Event('change', { bubbles: true }));

            console.log(`Injected into "${label}":`, valueToInject);
        });
        console.groupEnd();
    })();