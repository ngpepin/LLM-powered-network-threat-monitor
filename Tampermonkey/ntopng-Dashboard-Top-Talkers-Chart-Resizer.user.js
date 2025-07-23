// ==UserScript==
// @name         ntopng Dashboard Focus: Top Flow Talkers
// @namespace    http://tampermonkey.net/
// @version      1.0
// @description  Expand Top Flow Talkers and hide other widgets on ntopng dashboard
// @author       you
// @match        http://192.168.0.1:3000/lua/index.lua*
// @grant        none
// ==/UserScript==

(function () {
    'use strict';
    console.log('✅ Tampermonkey: Initializing ntopng dashboard override');

    function resizeSVGForcefully() {
        const widgetContainers = [...document.querySelectorAll('.col-6.widget-box-main-dashboard.drag-item')];
        const flowWidget = widgetContainers.find(el => el.innerText.includes('Top Flow Talkers'));

        if (!flowWidget) {
            console.warn('⚠️ Top Flow Talkers widget not found');
            return;
        }

        // Resize container
        flowWidget.classList.remove('col-6');
        flowWidget.classList.add('col-12');

        const box = flowWidget.querySelector('.widget-box');
        if (box) {
            box.style.width = '100%';
            box.style.height = '800px';
        }

        // Resize SVG
        const svg = flowWidget.querySelector('svg');
        if (svg) {
            svg.removeAttribute('width');
            svg.removeAttribute('height');
            svg.setAttribute('preserveAspectRatio', 'xMidYMid meet');
            svg.setAttribute('viewBox', `0 0 1800 600`);
            svg.style.width = '215%';
            svg.style.height = '215%';
            console.log('🔁 Forced resize applied to SVG');
        } else {
            console.warn('⚠️ SVG element not found yet in widget');
        }
    }

    // Run initially and then poll every second
    setInterval(resizeSVGForcefully, 1000);
})();