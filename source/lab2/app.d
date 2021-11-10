import std.range;
import std.algorithm;
import std.random;
import std.string;
import std.stdio;
import std.conv;
import std.digest.md;
import std.digest.sha;

import common.aes;
import common.util;
import skid;
import lamport;

import arsd.minigui;


struct VerticalList
{
    TextLabel label;
    VerticalLayout layout;
    int height;
    int blockSize;
}

VerticalList verticalList(string text, int height, int blockSize, Widget parent)
{
    VerticalList list;
    list.label = new TextLabel(text, TextAlignment.Left, parent);
    list.layout = new VerticalLayout(parent);
    list.height = height;
    list.blockSize = blockSize;

    foreach (y; 0..height)
    foreach (i; 0..blockSize)
        new TextLabel("", TextAlignment.Left, list.layout);
    
    return list;
}

TextLabel getChildAt(ref VerticalList list, int y, int positionInBlock)
{
    assert(y < list.height);
    assert(positionInBlock < list.blockSize);
    return cast(TextLabel) list.layout.children[y * list.blockSize + positionInBlock];
}

void setTextAt(ref VerticalList list, int y, int positionInBlock, string text)
{
    getChildAt(list, y, positionInBlock).label(text);
}

string formatUlong4(in ulong[4] num)
{
    return format("0x%016x_%016x_%016x_%016x", num[3], num[2], num[1], num[0]);
}


struct LamportPage
{
    // Options
    enum size_t numShownNumbers = 4;

    // View
    ScrollableContainerWidget lamportPage;
    LabeledLineEdit messageField;
    LabeledLineEdit messageHashField;
    LabeledLineEdit messageHashBitsField;
    Button regenerateKeysButton;
    VerticalList privateKeyGrid;
    VerticalList publicKeyGrid;
    VerticalList signatureGrid;

    // Model
    ubyte[32] hash;
    alias Lamp = Lamport!sha256Of;
    LamportKey privateKey;
    LamportKey publicKey;
    LamportSignature signature;

    static void updateKeyList(ref VerticalList list, in LamportKey key)
    {
        string formatEntry(int i, in ulong[4] num)
        {
            return format("%d: 0x%016x_%016x_%016x_%016x", i, num[3], num[2], num[1], num[0]);
        }

        foreach (y; 0..list.height)
        foreach (i; 0..list.blockSize)
            list.setTextAt(y, i, formatEntry(i, key[y][i]));
    }

    void regenerateKeys()
    {
        privateKey = Lamp.generatePrivateKey();
        publicKey  = Lamp.generatePublicKey(privateKey);
        updateKeyList(publicKeyGrid, publicKey);
        updateKeyList(privateKeyGrid, privateKey);
    }

    void regenerateSignature()
    {
        auto message = messageField.content.representation;
        hash = sha256Of(message);
        messageHashField.content(hash.toHexString!(LetterCase.lower));
        
        auto firstUlong = (cast(ulong[1]) hash[0..8])[0];
        char[numShownNumbers + 3] shownHashBits = '.';
        foreach (bitIndex; 0..numShownNumbers)
            shownHashBits[bitIndex] = ((firstUlong >> bitIndex) & 1) + '0';
        messageHashBitsField.content(shownHashBits.idup);

        signature = Lamp.generateSignature(message, privateKey);
        foreach (y; 0..numShownNumbers)
            signatureGrid.setTextAt(cast(int) y, 0, formatUlong4(signature[y]));
    }

    this(TabWidgetPage parent)
    {
        lamportPage = new ScrollableContainerWidget(parent);

        messageField         = new LabeledLineEdit("Message", lamportPage);
        messageHashField     = new LabeledLineEdit("Message Hash", lamportPage);
        messageHashBitsField = new LabeledLineEdit("Message Hash Bits", lamportPage);
        regenerateKeysButton = new Button("Regenerate Keys", lamportPage);

        signatureGrid  = verticalList("Signature", numShownNumbers, 1, lamportPage);
        privateKeyGrid = verticalList("Private Key", numShownNumbers, 2, lamportPage);
        publicKeyGrid  = verticalList("Public Key", numShownNumbers, 2, lamportPage);

        messageField.addEventListener(EventType.change, &regenerateSignature);
        regenerateKeysButton.addEventListener((ClickEvent ev) 
        { 
            if (ev.button == MouseButton.left)
            {
                regenerateKeys(); 
                regenerateSignature();
            }
        });
        regenerateKeys();
        regenerateSignature();
    }
}


// 1. Enchange numbers.
// 2. Send hash    Bob -> Alice.
// 3. Verify hash  of Bob by Alice.
// 4. Send hash    Alice -> Bob.
// 5. Verify hash  of Alice by Bob.
struct SkidPage
{
    // View
    // ScrollableContainerWidget container;
    LabeledLineEdit aesKey;
    Button regenerateRandomNumbers;
    TableView stepsContainer;

    // Model
    SKID!(MD5, AESWrapper)[2] contexts;

    void resetAesKey()
    {
        auto keyText = aesKey.content;
        if (keyText.length > 16)
        {
            keyText = keyText[0..16];
            aesKey.content(keyText);
        }
        ubyte[16] key = 0;
        key[0..keyText.length] = keyText.representation[];

        foreach (ref context; contexts)
            context._blockCipher = AESWrapper(createEncryptionContext(key));
    }

    void resetRandomNumbers()
    {
        foreach (ref context; contexts)
            context._ownRandomNumber = uniform!ulong;
    }

    this(TabWidgetPage parent)
    {
        auto container = parent;
        aesKey = new LabeledLineEdit("AES key", container);
        regenerateRandomNumbers = new Button("Regenerate random numbers", container);
        stepsContainer = new TableView(container);

        contexts[0]._digest = MD5();
        contexts[1]._digest = MD5();
        contexts[0]._ownName = "Alice".representation;
        contexts[1]._ownName = "Bob".representation;

        stepsContainer.setColumnInfo([
            TableView.ColumnInfo("Step", 100, TextAlignment.Center),
            TableView.ColumnInfo("Alice", 150, TextAlignment.Center),
            TableView.ColumnInfo("Bob", 150, TextAlignment.Center)
        ]);
        stepsContainer.setItemCount(3);
        stepsContainer.getData = delegate (int row, int column, scope void delegate(in char[]) sink) 
        {
            writeln("Called ", row, " ", column);
            if (column == 0)
            {
                static immutable StepStrings = [
                    "1: number exchange",
                    "2: Alice validates Bob",
                    "3: Bob validates Alice"
                ];
                return sink(StepStrings[row]);
            }
            // random numbers
            if (row == 0)
            {
                sink(format("0x%016x", contexts[column]._ownRandomNumber));
            }
            // hash
            else if (row == 1)
            {
                auto hash = contexts[1].computeHashA(contexts[0]._ownRandomNumber); 

                if (column == 1)
                    sink(hash.toHexString!(LetterCase.lower));
                else
                    sink(contexts[0].validateHashA(hash, contexts[1]._ownRandomNumber, contexts[1]._ownName) 
                        ? "Validated" : "Not validated");
            }
            else if (row == 2)
            {
                auto hash = contexts[0].computeHashB(contexts[1]._ownRandomNumber); 

                // This is going to be the same, 
                if (column == 0)
                    sink(hash.toHexString!(LetterCase.lower));
                else
                    sink(contexts[1].validateHashB(hash, contexts[0]._ownName) 
                        ? "Validated" : "Not validated");
            }
        };

        aesKey.addEventListener(EventType.change, 
        {
            resetAesKey();
            // stepsContainer.update(); 
        });

        regenerateRandomNumbers.addEventListener((ClickEvent ev)
        {
            if (ev.button == MouseButton.left)
            {
                resetRandomNumbers();
                // stepsContainer.update(); 
            }
        });

        resetAesKey();
        resetRandomNumbers();
        // stepsContainer.update(); 
    }
}

void main(string[] args)
{
    auto window = new MainWindow();
    window.title("Authorization protocols showoff");

    auto tabs = new TabWidget(window);
    auto lamportPage = new LamportPage(tabs.addPage("Lamport"));
    auto skidPage = new SkidPage(tabs.addPage("Skid"));
    
    
    window.addEventListener((KeyDownEvent ev) 
    {
        if (ev.key == Key.Escape)
            window.close();
    });
	window.loop();
}
