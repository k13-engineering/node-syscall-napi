import nodeFs from "node:fs";

if (process.argv.length !== 4) {
  console.error(`Usage: node ${process.argv[1]} <path-to-binary> <export-name>`);
  process.exit(1);
}

const binaryPath = process.argv[2];
const exportName = process.argv[3];

const binaryContent = await nodeFs.promises.readFile(binaryPath);

const base64Content = binaryContent.toString("base64");

const tsContent = `

// eslint-disable-next-line k13-engineering/prefer-typed-arrays
const buf = Buffer.from("${base64Content}", "base64");

const ${exportName} = new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);

export {
  ${exportName}
};\n
`;

process.stdout.write(tsContent);
