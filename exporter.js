const target_ = document.querySelector('#test');
if (!target_) {
    // 直接append到body
    const div = document.createElement('textarea');
    div.id = 'test';
    div.style.width = "100%";
    div.style.height = "300px";
    div.textContent = "QQ号,昵称,\n";
    document.body.appendChild(div);
}
const element = document.querySelector('.t-table__body');
function runn() {
    const target = document.querySelector('#test');
    const table = document.querySelectorAll('table')[0];
    if (!table) {
    console.error("未找到表格");
    }
    let result = "";

    // 遍历表格中的每一行
    table.querySelectorAll('tr').forEach(row => {
    const tds = row.querySelectorAll('td');
    if (tds.length < 3) return; // 跳过无效行（如表头）

    // 提取QQ号
    let qqId = null;
    const qqP = [...tds[1].querySelectorAll('p')].find(p => p.textContent.includes('QQ:'));
    if (qqP) {
        const match = qqP.textContent.match(/QQ:(\d+)/);
        if (match) {
        qqId = match[1];
        }
    }

    // 提取昵称
    const nicknameSpan = tds[2].querySelector('span');
    const nickname = nicknameSpan ? nicknameSpan.textContent.trim().split('#')[0].split('＃')[0] : null;

    // 输出格式化结果
    if (qqId && nickname) {
        result += (`${qqId},${nickname},\n`);
    }
    });
    target.textContent += result;
    console.log("处理成功");
}
const observer = new MutationObserver((mutations) => {runn()});

// 配置观察选项：监听子节点变化、属性变化等
observer.observe(element, {
  childList: true,      // 监听子节点增删
  subtree: true,        // 监听所有后代节点
  characterData: true   // 监听文本内容变化
});
runn();