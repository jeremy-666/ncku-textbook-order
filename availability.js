const openingDate = "2026-08-20";

function getTaipeiDate() {
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone: "Asia/Taipei",
    year: "numeric",
    month: "2-digit",
    day: "2-digit"
  }).formatToParts(new Date());
  const value = (type) => parts.find((part) => part.type === type).value;
  return `${value("year")}-${value("month")}-${value("day")}`;
}

if (getTaipeiDate() < openingDate) {
  const notice = document.createElement("div");
  notice.className = "availability-notice";
  notice.setAttribute("role", "alertdialog");
  notice.setAttribute("aria-modal", "true");
  notice.innerHTML = `
    <section class="availability-card">
      <div class="notice-mark" aria-hidden="true">成</div>
      <h2>系統尚未開放</h2>
      <p>系統 8/20 以後才會開啟喔。<br />請於 2026 年 8 月 20 日後再回來預訂教科書。</p>
    </section>`;
  document.body.appendChild(notice);
}
