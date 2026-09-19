import { connect } from 'cloudflare:sockets';
//说明：抛弃了ed配置，不要设置/?ed=2560，xhttp不适合pages部署，理论上也支持Snippets付费版
let 哎呀呀这是我的VL密钥 = "ae23a15c-cbcc-4dd7-bb51-5b70cc0a62a8";

let 启用反代功能 = true //选择是否启用反代功能【总开关】，false，true，现在你可以自由的选择是否启用反代功能了
let 反代地址列表 = [ //支持域名，IP，IP段，适当填写
  "ProxyIP.JP.CMLiussss.net",
  //"104.22.132.0/24",
  //"104.23.243.0/24",
  "162.158.111.0/24",
  //"162.158.85.0/24",
  //"162.159.124.0/24",
  "172.64.201.0/24",
  //"172.71.131.0/24",
  //"172.71.237.0/24"
];

let 初始传输阈值 = 4 //单位M，先传输一定数据后再转化为管道流模式
//////////////////////////////////////////////////////////////////////////主要架构////////////////////////////////////////////////////////////////////////
globalThis.反代缓存 ??= '';
export default {
  async fetch(访问请求) {
    if (访问请求.method === 'POST' && 访问请求.body) {
      return await 处理数据(访问请求);
    } else {
      return new Response('Hello World!', { status: 200 });
    }
  }
};
async function 处理数据(访问请求) {
  try {
    const 读取器 = 访问请求.body.getReader();
    const 请求数据 = (await 读取器.read()).value;
    const 解析首包 = await 解析首包数据(new Uint8Array(请求数据));
    const 传输数据 = 解析首包.TCP接口.writable.getWriter();
    await 传输数据.write(解析首包.初始数据);
    读取器.releaseLock();
    传输数据.releaseLock();
    访问请求.body.pipeTo(解析首包.TCP接口.writable);
    return new Response(await 数据回传通道(解析首包.TCP接口, 解析首包.版本号));
  } catch (e) {
    return new Response(`拒绝访问：${e}`, { status: 400 });
  }
  async function 数据回传通道 (TCP接口, 版本号) {
    const 读取管道 = new IdentityTransformStream();
    动态回传(TCP接口, 版本号, 读取管道)
    return 读取管道.readable;
  }
  async function 动态回传(TCP接口, 版本号, 读取管道) {
    let 累计接收字节数 = 0;
    const 读取数据 = TCP接口.readable.getReader({ mode: "byob" });
    const 写入器 = 读取管道.writable.getWriter();
    写入器.write(new Uint8Array([版本号, 0]));
    const 读取缓存大小 = 64*1024;
    let 创建复用缓存 = new ArrayBuffer(读取缓存大小)
    while (true) {
      const { done: 流结束, value: 返回数据 } = await 读取数据.read(new Uint8Array(创建复用缓存));
      if (流结束) break;
      累计接收字节数 += 返回数据.length;
      创建复用缓存 = new ArrayBuffer(读取缓存大小)
      写入器.write(返回数据);
      if (累计接收字节数 >= 初始传输阈值*1024*1024) break;
    }
    写入器.releaseLock();
    读取数据.releaseLock();
    TCP接口.readable.pipeTo(读取管道.writable)
  }
}
async function 解析首包数据(二进制数据) {
  let 识别地址类型, 访问地址, 地址长度;
  if (二进制数据.length < 32) throw new Error('数据长度不足');
  const 获取协议头 = 二进制数据[0];
  const 验证VL的密钥 = (a, i = 0) => [...a.slice(i, i + 16)].map(b => b.toString(16).padStart(2, '0')).join('').replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/, '$1-$2-$3-$4-$5');
  if (验证VL的密钥(二进制数据.slice(1, 17)) !== 哎呀呀这是我的VL密钥) throw new Error('UUID验证失败');
  const 提取端口索引 = 18 + 二进制数据[17] + 1;
  const 访问端口 = new DataView(二进制数据.buffer, 提取端口索引, 2).getUint16(0);
  const 提取地址索引 = 提取端口索引 + 2;
  识别地址类型 = 二进制数据[提取地址索引];
  let 地址信息索引 = 提取地址索引 + 1;
  switch (识别地址类型) {
    case 1:
      地址长度 = 4;
      访问地址 = 二进制数据.slice(地址信息索引, 地址信息索引 + 地址长度).join('.');
      break;
    case 2:
      地址长度 = 二进制数据[地址信息索引];
      地址信息索引 += 1;
      访问地址 = new TextDecoder().decode(二进制数据.slice(地址信息索引, 地址信息索引 + 地址长度));
      break;
    case 3:
      地址长度 = 16;
      const ipv6 = [];
      const 读取IPV6地址 = new DataView(二进制数据.buffer, 地址信息索引, 16);
      for (let i = 0; i < 8; i++) ipv6.push(读取IPV6地址.getUint16(i * 2).toString(16));
      访问地址 = ipv6.join(':');
      break;
    default:
      throw new Error ('无效的访问地址');
  }
  const 写入初始数据 = 二进制数据.slice(地址信息索引 + 地址长度);
  const TCP接口 = await 创建TCP接口连接(访问地址, 访问端口, 识别地址类型);
  console.log(`访问地址: ${访问地址}:${访问端口}，地址类型: ${识别地址类型}`);
  return { 版本号: 获取协议头, TCP接口: TCP接口, 初始数据: 写入初始数据 };
}
async function 创建TCP接口连接(访问地址, 访问端口, TCP接口) {
  try {
    const 解析IP = 匹配地址(访问地址);
    if (解析IP.类型 === 'ipv6') 解析IP.地址 = `[${解析IP.地址}]`
    TCP接口 = connect({ hostname: 解析IP.地址, port: 访问端口 });
    await TCP接口.opened;
  } catch {
    if (启用反代功能) {
      try {
        TCP接口 = connect({ hostname: globalThis.反代缓存, port: 443 });
        await TCP接口.opened;
      } catch {
        TCP接口 = await 轮询反代IP连接();
      }
    }
  }
  return TCP接口;
}
async function 轮询反代IP连接() {
  const 并发数量 = 100;
  for (const 地址段 of 反代地址列表) {
    const IP列表 = 展开地址段(地址段);
    for (let i = 0; i < IP列表.length; i += 并发数量) {
      const 当前IP列表 = IP列表.slice(i, i + 并发数量);
      const TCP接口列表 = [];
      const 连接任务 = 当前IP列表.map(async IP => {
        try {
          const TCP接口 = connect({ hostname: IP, port: 443 });
          TCP接口列表.push(TCP接口);
          await TCP接口.opened;
          return { IP, TCP接口 };
        } catch {
          return null;
        }
      });
      const 结果 = await Promise.any(
        连接任务.map(async 任务 => {
          const 结果 = await 任务;
          if (!结果) throw new Error();
          return 结果;
        })
      ).catch(() => null);
      if (结果) {
        globalThis.反代缓存 = 结果.IP;
        for (const TCP接口 of TCP接口列表) {
          if (TCP接口 !== 结果.TCP接口) {
            try { TCP接口?.close() } catch {};
          }
        }
        return 结果.TCP接口;
      }
    }
  }
}
function 展开地址段(地址段) {
  if (!地址段.includes("/")) return [地址段];
  const [IP, 位数] = 地址段.split("/");
  const 前缀长度 = Number(位数);
  const [a, b, c, d] = IP.split(".").map(Number);
  const IP数字 = (((a << 24) >>> 0) | (b << 16) | (c << 8) | d) >>> 0;
  const 掩码 = 前缀长度 === 0 ? 0 : (0xFFFFFFFF << (32 - 前缀长度)) >>> 0;
  const 网络地址 = IP数字 & 掩码;
  const 数量 = 2 ** (32 - 前缀长度);
  const IP列表 = [];
  for (let i = 1; i < 数量 - 1; i++) {
    const n = (网络地址 + i) >>> 0;
    IP列表.push(`${n >>> 24}.${(n >>> 16) & 255}.${(n >>> 8) & 255}.${n & 255}`);
  }
  return IP列表;
}
function 匹配地址(地址) {
  const 匹配 = 地址.match(/^(?:\[(?<ipv6>(?!fc00:)(?!fd00:)(?!fe80:)(?!::1)(?!0:)[0-9a-fA-F:]+)\]|(?<ipv6>(?!fc00:)(?!fd00:)(?!fe80:)(?!::1)(?!0:)[0-9a-fA-F:]+)|(?<ipv4>(?!10\.)(?!127\.)(?!169\.254\.)(?!172\.(1[6-9]|2\d|3[0-1])\.)(?!192\.168\.)(?!0\.)\d{1,3}(?:\.\d{1,3}){3})|(?<domain>[a-zA-Z0-9.-]+))(?::(?<port>\d+))?$/);  
  const { ipv6, ipv4, domain, port } = 匹配.groups;
  function 展开IPv6(ip) {
    ip = ip.replace(/^\[|\]$/g, '');
    if (ip.includes('::')) {
      const [前, 后] = ip.split('::');
      const 前段 = 前 ? 前.split(':') : [];
      const 后段 = 后 ? 后.split(':') : [];
      const 缺失数量 = 8 - (前段.length + 后段.length);
      const 填充 = Array(缺失数量).fill('0');
      ip = [...前段, ...填充, ...后段].join(':');
    }
    return ip
      .split(':')
      .map(x => x.padStart(4, '0').toLowerCase())
      .join(':');
  }
  const 展开IPv6地址 = ipv6 ? 展开IPv6(ipv6) : null;
  return {
    类型: ipv6 ? 'ipv6' : ipv4 ? 'ipv4' : '域名',
    地址: 展开IPv6地址 || ipv4 || domain,
    端口: port ? Number(port) : 443
  };
}
