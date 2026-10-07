export function download(name: string, parts: BlobPart[], type: string): void {
  const url = URL.createObjectURL(new Blob(parts, { type }));
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}
