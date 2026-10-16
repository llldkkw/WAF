import { useEffect, useState } from "react";
import QRCode from "qrcode";
import type { Enrollment } from "../lib/api";
import { Button, Modal } from "./ui";

/** Shows a freshly generated TOTP secret once, as a QR code. */
export function TotpEnroll({ data, onClose }: { data: Enrollment | null; onClose: () => void }) {
  const [img, setImg] = useState("");
  useEffect(() => {
    if (!data) return;
    QRCode.toDataURL(data.totp_url, { margin: 1, width: 220, errorCorrectionLevel: "M" }).then(setImg);
  }, [data]);
  if (!data) return null;
  return (
    <Modal open onClose={onClose} title={`为 ${data.user.username} 设置两步验证`} footer={<Button variant="primary" onClick={onClose}>我已保存</Button>}>
      <div className="flex flex-col items-center text-center gap-4">
        <p className="text-sm text-muted">请使用 Google Authenticator、Microsoft Authenticator 或 1Password 扫描二维码。此二维码只显示一次。</p>
        {img && <img src={img} alt="TOTP 二维码" className="rounded-xl bg-white p-2 size-[220px]" />}
        <div className="w-full">
          <div className="text-xs text-muted mb-1">无法扫码时手动输入密钥</div>
          <code className="block w-full font-mono text-sm bg-surface-2 rounded-lg px-3 py-2 break-all select-all">{data.totp_secret}</code>
        </div>
      </div>
    </Modal>
  );
}
