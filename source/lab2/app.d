import std.range;
import std.algorithm;
import std.random;
import std.string;
import std.stdio;
import std.conv;
import std.digest.sha;

import common.util;
import skid;
import lamport;

import arsd.minigui;

struct TextGrid
{
    GridLayout layout;
    void setText(int x, int y, string str)
    {
        writeln(layout.getChildAtPosition(x, y));
        (cast(TextLabel) layout.getChildAtPosition(x, y)).label(str);
    }
}

TextGrid textGrid(int width, int height, Widget parent)
{
    TextGrid result = void;
    result.layout = new GridLayout(width, height, parent);
    foreach (x; 0..width)
    foreach (y; 0..height)
    {
        auto label = new TextLabel(x.to!string, TextAlignment.Center, result.layout);
        result.layout.setChildPosition(label, x, y, 1, 1);
    }
    return result;
}

void main(string[] args)
{
    auto window = new MainWindow();
    window.title("Authorization protocols showoff");

    auto tabs = new TabWidget(window);
    auto lamportPage = tabs.addPage("Lamport");

    enum numShownNumbers = 5;
    ubyte[32] hash;
    alias Lamp = Lamport!sha256Of;
    LamportKey privateKey = Lamp.generatePrivateKey();
    LamportKey publicKey = Lamp.generatePublicKey(privateKey);
    LamportSignature signature;

    auto messageField         = new LabeledLineEdit("Message", lamportPage);
    auto messageHashField     = new LabeledLineEdit("Message Hash", lamportPage);
    auto messageHashBitsField = new LabeledLineEdit("Message Hash Bits", lamportPage);

    TableView.ColumnInfo[numShownNumbers] columnInfos;
    foreach (index, ref columnInfo; columnInfos)
    {
        columnInfo.alignment = TextAlignment.Center;
        columnInfo.name = index.to!string;
        columnInfo.width
    }

    auto privateKeyGridLabel  = new TextLabel("Private Key", TextAlignment.Left, lamportPage); 
    auto privateKeyGrid       = new TableView(lamportPage);
    privateKeyGrid.setColumnInfo()

    auto publicKeyGridLabel   = new TextLabel("Public Key", TextAlignment.Left, lamportPage); 
    auto publicKeyGrid        = textGrid(numShownNumbers, 2, lamportPage);

    auto signatureGridLabel   = new TextLabel("Signature", TextAlignment.Left, lamportPage); 
    auto signatureGrid        = textGrid(numShownNumbers, 1, lamportPage);
    

    messageField.addEventListener(EventType.change, 
    {
        auto message = messageField.content.representation;
        hash = sha256Of(message);
        messageHashField.content(hash.toHexString!(LetterCase.lower));
        
        auto firstUlong = (cast(ulong[1]) hash[0..8])[0];
        char[numShownNumbers + 3] shownHashBits = '.';
        foreach (bitIndex; 0..numShownNumbers)
            shownHashBits[bitIndex] = ((firstUlong >> bitIndex) & 1) + '0';
        messageHashBitsField.content(shownHashBits.idup);

        auto signature = Lamp.generateSignature(message, privateKey);
        foreach (numberIndex; 0..numShownNumbers)
            signatureGrid.setText(numberIndex, 0, signature[numberIndex].to!string);
    });

    window.addEventListener((KeyDownEvent ev) {
        if (ev.key == Key.Escape)
            window.close();
    });

	window.loop();
}
