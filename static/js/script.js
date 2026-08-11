document.addEventListener("DOMContentLoaded", function () {

    // =========================================================
    // ELEMENTS
    // =========================================================

    const scanForm = document.getElementById("scan-form");
    const scanInput = document.getElementById("scan-input");
    const charCount = document.getElementById("char-count");

    const resultContainer =
        document.getElementById("result-ui-container");

    const resultScore =
        document.getElementById("result-score");

    const resultBadge =
        document.getElementById("result-badge");

    const whyContent =
        document.getElementById("why-content");

    const evidenceTags =
        document.getElementById("evidence-tags");

    const recsList =
        document.getElementById("recs-list");

    const analyzeBtn =
        document.getElementById("analyze-btn");

    const btnText =
        document.getElementById("btn-text");

    const btnSpinner =
        document.getElementById("btn-spinner");

    const tabs =
        document.querySelectorAll(".tab-btn");

    let selectedType = "message";


    // =========================================================
    // TAB SWITCHING
    // =========================================================

    tabs.forEach(function (tab) {

        tab.addEventListener("click", function () {

            tabs.forEach(function (item) {
                item.classList.remove("active");
            });

            tab.classList.add("active");

            selectedType =
                tab.getAttribute("data-type");

            updateInputPlaceholder();
        });

    });


    // =========================================================
    // PLACEHOLDER
    // =========================================================

    function updateInputPlaceholder() {

        if (selectedType === "message") {

            scanInput.placeholder =
                "Example: URGENT! Your account will be suspended within 24 hours. Verify your OTP and password immediately.";

        }

        else if (selectedType === "url") {

            scanInput.placeholder =
                "Example: http://paypa1-security.xyz/login";

        }

        else if (selectedType === "ecommerce") {

            scanInput.placeholder =
                "Example: iPhone 15 90% OFF! Only today! Pay now using gift card. No refunds.";

        }
    }


    // =========================================================
    // CHARACTER COUNTER
    // =========================================================

    if (scanInput) {

        scanInput.addEventListener("input", function () {

            if (charCount) {
                charCount.textContent =
                    scanInput.value.length;
            }

        });

    }


    // =========================================================
    // FORM SUBMIT
    // =========================================================

    if (scanForm) {

        scanForm.addEventListener("submit", async function (event) {

            event.preventDefault();

            const content =
                scanInput.value.trim();

            if (!content) {

                alert(
                    "Please enter a message, URL, or e-commerce content."
                );

                return;
            }


            // -------------------------------------------------
            // BUTTON LOADING STATE
            // -------------------------------------------------

            analyzeBtn.disabled = true;

            if (btnText) {
                btnText.style.display = "none";
            }

            if (btnSpinner) {
                btnSpinner.style.display = "inline";
            }


            try {

                // =================================================
                // SEND DATA TO FLASK
                // =================================================

                const response = await fetch(
                    "/api/analyze",
                    {
                        method: "POST",

                        headers: {
                            "Content-Type":
                                "application/json"
                        },

                        body: JSON.stringify({
                            type: selectedType,
                            content: content
                        })
                    }
                );


                // =================================================
                // READ SERVER RESPONSE
                // =================================================

                const result =
                    await response.json();


                if (!response.ok) {

                    throw new Error(
                        result.message ||
                        "Analysis failed."
                    );
                }


                if (
                    result.status !== "success"
                    || !result.data
                ) {

                    throw new Error(
                        "Invalid response from server."
                    );
                }


                // =================================================
                // DISPLAY REAL AI RESULT
                // =================================================

                displayResult(
                    result.data
                );


            }

            catch (error) {

                console.error(
                    "ScamShield API Error:",
                    error
                );

                alert(
                    "Could not analyze the content.\n\n" +
                    error.message
                );

            }

            finally {

                analyzeBtn.disabled = false;

                if (btnText) {
                    btnText.style.display = "inline";
                }

                if (btnSpinner) {
                    btnSpinner.style.display = "none";
                }

            }

        });

    }


    // =========================================================
    // DISPLAY RESULT
    // =========================================================

    function displayResult(data) {

        console.log(
            "REAL SCAMSHIELD RESULT:",
            data
        );


        // -------------------------------------------------
        // SHOW RESULT CARD
        // -------------------------------------------------

        if (resultContainer) {

            resultContainer.style.display =
                "block";

            resultContainer.scrollIntoView({
                behavior: "smooth",
                block: "start"
            });

        }


        // -------------------------------------------------
        // SCORE
        // -------------------------------------------------

        const score =
            Number(data.risk_score) || 0;

        if (resultScore) {

            resultScore.textContent =
                score;

        }


        // -------------------------------------------------
        // RISK LEVEL
        // -------------------------------------------------

        const riskLevel =
            String(
                data.risk_level || "SAFE"
            ).toUpperCase();


        // -------------------------------------------------
        // BADGE
        // -------------------------------------------------

        if (resultBadge) {

            resultBadge.textContent =
                riskLevel;

            resultBadge.classList.remove(
                "badge-safe",
                "badge-suspicious",
                "badge-high"
            );


            if (riskLevel === "SAFE") {

                resultBadge.classList.add(
                    "badge-safe"
                );

            }

            else if (
                riskLevel === "SUSPICIOUS"
            ) {

                resultBadge.classList.add(
                    "badge-suspicious"
                );

            }

            else {

                resultBadge.classList.add(
                    "badge-high"
                );

            }

        }


        // -------------------------------------------------
        // WHY FLAGGED
        // -------------------------------------------------

        if (whyContent) {

            const explanations =
                data.explanations || [];

            if (
                Array.isArray(explanations)
                && explanations.length > 0
            ) {

                whyContent.textContent =
                    explanations.join(" ");

            }

            else {

                whyContent.textContent =
                    data.summary ||
                    "No major indicators detected.";

            }

        }


        // -------------------------------------------------
        // EVIDENCE TAGS
        // -------------------------------------------------

        if (evidenceTags) {

            evidenceTags.innerHTML = "";

            const tags =
                data.evidence_tags || [];


            if (
                Array.isArray(tags)
                && tags.length > 0
            ) {

                tags.forEach(function (tag) {

                    const span =
                        document.createElement("span");

                    span.className =
                        "tag";

                    span.textContent =
                        tag;

                    evidenceTags.appendChild(
                        span
                    );

                });

            }

        }


        // -------------------------------------------------
        // RECOMMENDATIONS
        // -------------------------------------------------

        if (recsList) {

            recsList.innerHTML = "";

            const recommendations =
                data.recommendations || [];


            if (
                Array.isArray(recommendations)
                && recommendations.length > 0
            ) {

                recommendations.forEach(
                    function (recommendation) {

                        const li =
                            document.createElement("li");

                        const icon =
                            document.createElement("i");

                        icon.className =
                            "fa-solid fa-circle-check";

                        icon.style.marginRight =
                            "8px";

                        li.appendChild(icon);

                        li.appendChild(
                            document.createTextNode(
                                recommendation
                            )
                        );

                        recsList.appendChild(li);

                    }
                );

            }

        }

    }


    // =========================================================
    // CLEAR BUTTON
    // =========================================================

    window.clearScanForm = function () {

        if (scanInput) {

            scanInput.value = "";

        }

        if (charCount) {

            charCount.textContent = "0";

        }

        if (resultContainer) {

            resultContainer.style.display =
                "none";

        }

        updateInputPlaceholder();

    };


    // =========================================================
    // INITIAL SETUP
    // =========================================================

    updateInputPlaceholder();

});