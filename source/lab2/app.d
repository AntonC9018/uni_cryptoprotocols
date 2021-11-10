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


class BButton : Button
{
    this(string title, Widget container) { super(title, container); }
    override int maxHeight() { return 30; }
}

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
    BButton regenerateKeysButton;
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
        regenerateKeysButton = new BButton("Regenerate Keys", lamportPage);

        signatureGrid  = verticalList("Signature (the first %d numbers)".format(numShownNumbers), numShownNumbers, 1, lamportPage);
        privateKeyGrid = verticalList("Private Key (the first %d*2 numbers)".format(numShownNumbers), numShownNumbers, 2, lamportPage);
        publicKeyGrid  = verticalList("Public Key (the first %d*2 hashes)".format(numShownNumbers), numShownNumbers, 2, lamportPage);

        messageField.addEventListener(EventType.change, &regenerateSignature);
        regenerateKeysButton.addEventListener(EventType.triggered,
        { 
            regenerateKeys(); 
            regenerateSignature();
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
    BButton regenerateRandomNumbers;
    TableView stepsContainer;

    // Model
    SKID!(MD5, AESWrapper)[2] contexts;
    struct TableModel
    {
        string number;
        string hash;
        string validated;
    }
    TableModel[2] tableModels;
    string[3] getTableColumn(int column)
    {
        with (tableModels[column])
        {
            if (column == 0)
                return [number, validated, hash];
            else
                return [number, hash, validated];
        }
    }

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

    void updateModels()
    {
        foreach (i; 0..2)
            tableModels[i].number = format("0x%016x", contexts[i]._ownRandomNumber);
        
        auto hash0 = contexts[1].computeHashA(contexts[0]._ownRandomNumber);
        auto hash1 = contexts[0].computeHashB(contexts[1]._ownRandomNumber);

        tableModels[1].hash = hash0.toHexString!(LetterCase.lower).idup;
        tableModels[1].validated = contexts[1].validateHashB(hash1, contexts[0]._ownName)
            ? "Validated" : "Not validated";

        tableModels[0].hash = hash1.toHexString!(LetterCase.lower).idup;
        tableModels[0].validated = contexts[0].validateHashA(hash0, contexts[1]._ownRandomNumber, contexts[1]._ownName)
            ? "Validated" : "Not validated";
    }

    this(TabWidgetPage parent)
    {
        auto container = parent;
        aesKey = new LabeledLineEdit("AES key", container);
        regenerateRandomNumbers = new BButton("Regenerate random numbers", container);
        stepsContainer = new TableView(container);

        contexts[0]._digest = MD5();
        contexts[1]._digest = MD5();
        contexts[0]._ownName = "Alice".representation;
        contexts[1]._ownName = "Bob".representation;

        stepsContainer.setColumnInfo([
            TableView.ColumnInfo("Step", 150, TextAlignment.Center),
            TableView.ColumnInfo("Alice", 150, TextAlignment.Center),
            TableView.ColumnInfo("Bob", 150, TextAlignment.Center)
        ]);

        stepsContainer.getData = delegate (int row, int column, scope void delegate(in char[]) sink) 
        {
            if (column == 0)
            {
                static immutable StepStrings = [
                    "1: Number exchange",
                    "2: Alice validates Bob",
                    "3: Bob validates Alice"
                ];
                return sink(StepStrings[row]);
            }
            column--;
            sink(getTableColumn(column)[row]);
        };
        stepsContainer.setItemCount(3);

        aesKey.addEventListener(EventType.change, 
        {
            resetAesKey();
            updateModels();
            stepsContainer.update();
        });

        regenerateRandomNumbers.addEventListener(EventType.triggered,
        {
            resetRandomNumbers();
            updateModels();
            stepsContainer.update();
        });

        resetAesKey();
        resetRandomNumbers();
        updateModels();
    }
}

void main()
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
