function spanMark(text, keyword) {
  // 关键字高亮
  if (!keyword || !text) return text;
  const pattern = new RegExp(keyword, "gi");
  if (Number.isInteger(text)) text = text.toString();
  return text.replaceAll(
    pattern,
    (match) => `<span class="wheat">${match}</span>`
  );
}
const METHOD = 3; // 1: cell匹配 2: row匹配 3:table匹配
// 把数据插入到表中
function fillDataToTable(table_data, table, keyword = null) {
  const timeStart = new Date().getTime();
  // 如果没有数据，则提示为空
  if (table_data.length == 0) {
    table.innerHTML = '<br><span class="center">暂无筛选数据</span><br><br>';
    return;
  } else {
    table.innerHTML = "";
  }
  let thead = table.createTHead();
  var row = thead.insertRow();
  for (var i = 0; i < table_data[0].length; i++) {
    var th = document.createElement("th");
    th.innerHTML = table_data[0][i];
    row.appendChild(th);
  }
  table.appendChild(thead);

  document.querySelectorAll("th").forEach((th) => {
    th.style.cursor = "pointer";
    th.onclick = (e) => {
      sortTable(e.target);
    };
  });

  let tbody = document.createElement("tbody");
  for (let i = 1; i < table_data.length; i++) {
    let row = tbody.insertRow(-1);
    for (let j = 0; j < table_data[i].length; j++) {
      let cell = row.insertCell(j);
      let text = table_data[i][j];
      if (METHOD === 1) cell.innerHTML = spanMark(text, keyword);
      else cell.innerHTML = text;
      if (text && text.length > 16 && text[0] !== "<") {
        cell.classList.add("wrap");
      }
    }
    if (METHOD === 2) {
      row.innerHTML = spanMark(row.innerHTML, keyword);
    }
  }
  if (METHOD === 3) {
    tbody.innerHTML = spanMark(tbody.innerHTML, keyword);
  }
  tbody.innerHTML += `<span>(${METHOD})渲染${
    new Date().getTime() - timeStart
  }ms</span>`;
  table.appendChild(tbody);
}

// 输入表格的一个表头元素,以这个表头对表进行排序
function sortTable(element) {
  let index = Array.from(element.parentNode.children).indexOf(element);
  let table = element.parentNode.parentNode.parentNode;
  let tbody = table.children[1];
  let order = "asc";

  if (element.classList.contains("desc")) {
    element.classList.remove("desc");
    element.classList.add("asc");
    order = "asc";
    element.innerHTML = element.innerHTML.replace("▲", "▼");
  } else if (element.classList.contains("asc")) {
    element.classList.add("desc");
    element.classList.remove("asc");
    order = "desc";
    element.innerHTML = element.innerHTML.replace("▼", "▲");
  } else {
    Array.from(tbody.children[0].children).forEach((e) => {
      if (e.tagName === "TH") {
        e.classList.remove("asc");
        e.classList.remove("desc");
        e.innerHTML = e.innerHTML.replace(/▼|▲/g, "");
      }
    });
    element.classList.add("asc");
    element.innerHTML = element.innerHTML + "▼";
  }

  let td_arr = [];
  let row_count = tbody.rows.length;
  for (let i = 0; i < row_count; i++) {
    let cell = tbody.rows[i].cells[index].innerHTML;
    td_arr.push(cell);
  }

  let is_all_numbers = td_arr.every((str) => !isNaN(Number(str)));
  if (is_all_numbers) {
    td_arr = td_arr.map((str) => Number(str));
  }

  for (let i = 0; i < row_count - 1; i++) {
    for (let j = 0; j < row_count - 1 - i; j++) {
      if (order == "asc") {
        if (td_arr[j] < td_arr[j + 1]) {
          let temp = td_arr[j];
          td_arr[j] = td_arr[j + 1];
          td_arr[j + 1] = temp;
        }
      } else {
        if (td_arr[j] > td_arr[j + 1]) {
          let temp = td_arr[j];
          td_arr[j] = td_arr[j + 1];
          td_arr[j + 1] = temp;
        }
      }
    }
  }

  for (let item in td_arr) {
    for (let i = item; i < row_count; i++) {
      if (tbody.rows[i].cells[index].innerHTML == td_arr[item]) {
        tbody.insertBefore(tbody.rows[i], tbody.rows[parseInt(item)]);
        continue;
      }
    }
  }
}
function setupPageUtils(target, triggerFunction) {
  target.innerHTML = `<div style="display: flex;align-items: center;align-self: center;">
  <div class="btn" onclick="${triggerFunction}(event, '1')">&lt;&lt;</div> 
  <div class="btn" onclick="${triggerFunction}(event, '-')">&lt;</div>
  <input id="page-input" style="height: 30px;width: 12px;" type="text" min="1" value="1" oninput="this.style.width = (this.value.length * 8 + 4) + 'px'" onkeypress="${triggerFunction}(event)" onblur="${triggerFunction}(event)">
  <div id="page-num" >/1</div>
  <div class="btn" onclick="${triggerFunction}(event, '+')">&gt;</div>
  <div class="btn" onclick="${triggerFunction}(event, '-1')">&gt;&gt;</div>
  <select id="page-count" onchange="${triggerFunction}(event)">
    <option value="10" selected>10条/页</option>
    <option value="20">20条/页</option>
    <option value="50">50条/页</option>
    <option value="100">100条/页</option>
    <option value="200">200条/页</option>
    <option value="500">500条/页</option>
  </select>
</div>
`;
}
function getPageInfo(option) {
  // target的内容是 当前页/总页数
  let page_num = parseInt(document.querySelector("#page-input").value);
  let page_max = parseInt(
    document.querySelector("#page-num").textContent.slice(1)
  );
  if (option === "") {
    return;
  } else if (option == "-") {
    page_num--;
  } else if (option == "+") {
    page_num++;
  } else if (option !== null && !isNaN(option)) {
    if (option < 0) {
      page_num = page_max + 1 + parseInt(option);
    } else {
      page_num = parseInt(option);
    }
  }
  if (page_num > page_max) {
    page_num = page_max;
  } else if (page_num < 1) {
    page_num = 1;
  }
  page_count = parseInt(document.querySelector("#page-count").value);
  return { page: page_num, limit: page_count };
}
function updatePageData(page_max, page_num) {
  // 将result最前面加上分页信息
  document.querySelector("#page-input").value = page_num;
  if (page_max != null) {
    document.querySelector("#page-num").textContent = `/${page_max}`;
  }
}
