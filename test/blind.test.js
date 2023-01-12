const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("Token contract", function () {
  it("User's public key and company should be added to contract mapping", async function () {
    const [owner] = await ethers.getSigners();

    const verifier = await ethers.getContractFactory(
      "contracts/Verifier.sol:Verifier"
    );
    const v = await verifier.deploy();
    await v.deployed();

    console.log("Verifier.sol deployed to:", v.address);

    const blind = await ethers.getContractFactory("Blind");

    const bl = await blind.deploy(v.address);
    await bl.deployed();
    console.log("Blind.sol deployed to:", bl.address);

    const a = [
      "0x0a08163c892e678e5aa9a8aaa6711588a27048bd854694b27cc437b2e4671908",
      "0x241c35d4ecd96a287026fc26dff3d4aacbe4e6774b43a1cb4447a6b7542362cd",
    ];
    const b = [
      [
        "0x16494aec6bc66ef3c5367caa40e87ddc6295ebd17ef74d1d4909d746cb6d4781",
        "0x2e7be4557581ca692d289e3773946ccf99694d8f35f9ac2bb1ce4518e48bba6f",
      ],
      [
        "0x046ea21dbd94f313e4283a90cc5d8bd86e62070756b4165ebf5f0ffc59d45f53",
        "0x166a35b44e322094265129f1351a3b22a492eed10654d6b568a507483ffe6e75",
      ],
    ];
    const c = [
      "0x0e7cfa258e280d620949b5cbd8f905d9bc781e4816ac3021ab8f94952d9af702",
      "0x2ec3a0ba5286757371f92aeb6b347763b5e19b544a9616198a57fb7e758e5456",
    ];
    const input = [
      "0x0000000000000000000000000000000000c8430c6464e64ddda07a9b863d8881",
      "0x0000000000000000000000000000000001cd0da2c4ae4218b0cade824b613b37",
      "0x000000000000000000000000000000000062e5c346b31c47a050182d2eafd848",
      "0x00000000000000000000000000000000000618669ce3a3538eaddc8d6ced08b9",
      "0x0000000000000000000000000000000000d75cdc8d790c81ab9c23625464a414",
      "0x00000000000000000000000000000000011954a4b6d45c95fa48f63ffec9f0ad",
      "0x0000000000000000000000000000000001e075c1b0cf7069eac655ee53f6cb80",
      "0x000000000000000000000000000000000060409af02b53bf34965950c557a044",
      "0x000000000000000000000000000000000016b77d2e3917ea5af4e7363a68cffe",
      "0x00000000000000000000000000000000007283ffb204c691aaf1bce0ac279328",
      "0x0000000000000000000000000000000001785e45f8b6da078bb330084a557dbd",
      "0x00000000000000000000000000000000003520db147c498f546c95853efc64f3",
      "0x0000000000000000000000000000000001a652f8aede242fe83a7af1091cc560",
      "0x000000000000000000000000000000000177e578067b3fc1873b4838e2597d79",
      "0x000000000000000000000000000000000082c7f533459aff65a02e6f635fae51",
      "0x0000000000000000000000000000000000a00bcf4e84dc9a972a8eab541dfb33",
      "0x000000000000000000000000000000000000dbbace12b0ce3ef3dcde63800d8b",
      "0x0000000000000000000000000000000000000000000000000000000000000000",
      "0x0000000000000000000000000000000000000000000000000000000000000062",
      "0x0000000000000000000000000000000000000000000000000000000000000065",
      "0x0000000000000000000000000000000000000000000000000000000000000072",
      "0x000000000000000000000000000000000000000000000000000000000000006b",
      "0x0000000000000000000000000000000000000000000000000000000000000065",
      "0x000000000000000000000000000000000000000000000000000000000000006c",
      "0x0000000000000000000000000000000000000000000000000000000000000065",
      "0x0000000000000000000000000000000000000000000000000000000000000079",
      "0x0000000000000000000000000000000000000000000000000000000000000000",
      "0x0000000000000000000000000000000000000000000000000000000000000000",
      "0x0000000000000000000000000000000000000000000000000000000000000000",
      "0x0000000000000000000000000000000000000000000000000000000000000000",
      "0x0000000000000000000000000000000000000000000000000000000000000000",
      "0x0000000000000000000000000000000000000000000000000000000000000000",
      "0x0000000000000000000000000000000000000000000000000000000000000000",
      "0x0000000000000000000000000000000000000000000000000000000000000000",
      "0x0000000000000000000000000000000000000000000000000000000000000000",
      "0x0000000000000000000000000000000000000000000000000000000000000000",
      "0x0000000000000000000000000000000000000000000000000000000000000000",
      "0x0000000000000000000000000000000000000000000000000000000000000000",
      "0x0000000000000000000000000000000000000000000000000000000000000000",
      "0x0000000000000000000000000000000000000000000000000000000000000000",
      "0x0000000000000000000000000000000000000000000000000000000000000000",
      "0x0000000000000000000000000000000000000000000000000000000000000000",
      "0x0000000000000000000000000000000000000000000000000000000000000000",
      "0x0000000000000000000000000000000000000000000000000000000000000000",
      "0x0000000000000000000000000000000000000000000000000000000000000000",
      "0x0000000000000000000000000000000000000000000000000000000000000000",
      "0x0000000000000000000000000000000000000000000000000000000000000000",
      "0x0000000000000000000000000000000000000000000000000000000000000000",
    ];

    const add = await bl.add(a, b, c, input);
    console.log(add);

    const res = await bl.get(
      "0x0000000000000000000000000000000000000000"
    );
    console.log(res);

    expect(res).to.equal("berkeley");
  });
});