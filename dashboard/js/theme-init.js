/* PC Sentinel: restore display preferences before first paint (the theme is dark-only).
   - sidebar collapsed / expanded
   - background motion on / off (Settings › Display) */
(function () {
  var root = document.documentElement;
  try {
    if (localStorage.getItem('pcs-sidebar') === 'collapsed') root.setAttribute('data-sidebar', 'collapsed');
    root.setAttribute('data-fx', localStorage.getItem('pcs-fx') === 'off' ? 'off' : 'on');
  } catch (e) { /* storage blocked: defaults apply */ }
})();
