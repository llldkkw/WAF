import { countryName, flag } from "./format";

// ISO 3166-2:CN subdivision codes as returned by GeoLite2-City.
export const cnProvinces: Record<string, string> = {
  BJ: "北京", TJ: "天津", HE: "河北", SX: "山西", NM: "内蒙古", LN: "辽宁", JL: "吉林", HL: "黑龙江",
  SH: "上海", JS: "江苏", ZJ: "浙江", AH: "安徽", FJ: "福建", JX: "江西", SD: "山东", HA: "河南",
  HB: "湖北", HN: "湖南", GD: "广东", GX: "广西", HI: "海南", CQ: "重庆", SC: "四川", GZ: "贵州",
  YN: "云南", XZ: "西藏", SN: "陕西", GS: "甘肃", QH: "青海", NX: "宁夏", XJ: "新疆",
};

/** Human label for a geo rule: "CN" → 🇨🇳 中国, "CN-GD/深圳" → 🇨🇳 中国 · 广东 · 深圳. */
export function geoRuleLabel(rule: string) {
  const [area, city] = rule.split("/");
  const [cc, sub] = area.split("-");
  const parts = [countryName(cc) || cc];
  if (sub) parts.push(cc === "CN" ? cnProvinces[sub] ?? sub : sub);
  if (city) parts.push(city);
  return `${flag(cc)} ${parts.join(" · ")}`;
}

export function needsCityDB(rules: string[]) {
  return rules.some((r) => r.includes("-") || r.includes("/"));
}
