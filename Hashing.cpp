#include <stdint.h>
#include <stdio.h>
#include <iostream>
#include <conio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <fstream>
#include <ctime>

#include <windows.h>
#define SHA1CircularShift(bits,word) \
                (((word) << (bits)) | ((word) >> (32-(bits))))


#define SHA1HashSize 20
using namespace std;

 enum
{
    shaSuccess = 0,
    shaNull,            /* Null pointer parameter */
    shaInputTooLong,    /* input data too long */
    shaStateError       /* called Input after Result*/
};
typedef struct SHA
{
    uint32_t Intermediate_Hash[SHA1HashSize/4]; /* Message Digest  */

    uint32_t Length_Low;            /* Message length in bits      */
    uint32_t Length_High;           /* Message length in bits      */

                               /* Index into message block array   */
    int_least16_t Message_Block_Index;
    uint8_t Message_Block[64];      /* 512-bit message blocks      */

    int Computed;               /* Is the digest computed?         */
    int Corrupted;             /* Is the message digest corrupted? */
} SHA;

/*
 *  SHA1Reset
 *
 *  Description:
 *      This function will initialize the SHA in preparation
 *      for computing a new SHA1 message digest.
 *
 *  Parameters:
 *      context: [in/out]
 *          The context to reset.
 *
 *  Returns:
 *      sha Error Code.
 *
 */

int SHA1Reset(SHA *context)
{
    if (!context)
    {
        return shaNull;
    }

    context->Length_Low             = 0;
    context->Length_High            = 0;
    context->Message_Block_Index    = 0;

    context->Intermediate_Hash[0]   = 0x67452301;
    context->Intermediate_Hash[1]   = 0xEFCDAB89;
    context->Intermediate_Hash[2]   = 0x98BADCFE;
    context->Intermediate_Hash[3]   = 0x10325476;
    context->Intermediate_Hash[4]   = 0xC3D2E1F0;

    context->Computed   = 0;
    context->Corrupted  = 0;

    return shaSuccess;
}

/*
 *  SHA1ProcessMessageBlock
 *
 *  Description:
 *      This function will process the next 512 bits of the message
 *      stored in the Message_Block array.
 *
 *  Parameters:
 *      None.
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:

 *      Many of the variable names in this code, especially the
 *      single character names, were used because those were the
 *      names used in the publication.
 *
 *
 */
void SHA1ProcessMessageBlock(SHA *context)
{
    const uint32_t K[] =    {       /* Constants defined in SHA-1   */
                            0x5A827999,
                            0x6ED9EBA1,
                            0x8F1BBCDC,
                            0xCA62C1D6
                            };
    int           t;                 /* Loop counter                */
    uint32_t      temp;              /* Temporary word value        */
    uint32_t      W[80];             /* Word sequence               */
    uint32_t      A, B, C, D, E;     /* Word buffers                */

    /*
     *  Initialize the first 16 words in the array W
     */
    for(t = 0; t < 16; t++)
    {
        W[t] = context->Message_Block[t * 4] << 24;
        W[t] |= context->Message_Block[t * 4 + 1] << 16;
        W[t] |= context->Message_Block[t * 4 + 2] << 8;
        W[t] |= context->Message_Block[t * 4 + 3];
    }

    for(t = 16; t < 80; t++)
    {
       W[t] = SHA1CircularShift(1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
    }

    A = context->Intermediate_Hash[0];
    B = context->Intermediate_Hash[1];
    C = context->Intermediate_Hash[2];
    D = context->Intermediate_Hash[3];
    E = context->Intermediate_Hash[4];

    for(t = 0; t < 20; t++)
    {
        temp =  SHA1CircularShift(5,A) +
                ((B & C) | ((~B) & D)) + E + W[t] + K[0];
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);

        B = A;
        A = temp;
    }

    for(t = 20; t < 40; t++)
    {
        temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[1];
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }

    for(t = 40; t < 60; t++)
    {
        temp = SHA1CircularShift(5,A) +
               ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }

    for(t = 60; t < 80; t++)
    {
        temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[3];
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }

    context->Intermediate_Hash[0] += A;
    context->Intermediate_Hash[1] += B;
    context->Intermediate_Hash[2] += C;
    context->Intermediate_Hash[3] += D;
    context->Intermediate_Hash[4] += E;

    context->Message_Block_Index = 0;
}


/*
 *  SHA1PadMessage
 *

 *  Description:
 *      According to the standard, the message must be padded to an even
 *      512 bits.  The first padding bit must be a '1'.  The last 64
 *      bits represent the length of the original message.  All bits in
 *      between should be 0.  This function will pad the message
 *      according to those rules by filling the Message_Block array
 *      accordingly.  It will also call the ProcessMessageBlock function
 *      provided appropriately.  When it returns, it can be assumed that
 *      the message digest has been computed.
 *
 *  Parameters:
 *      context: [in/out]
 *          The context to pad
 *      ProcessMessageBlock: [in]
 *          The appropriate SHA*ProcessMessageBlock function
 *  Returns:
 *      Nothing.
 *
 */

void SHA1PadMessage(SHA *context)
{
    /*
     *  Check to see if the current message block is too small to hold
     *  the initial padding bits and length.  If so, we will pad the
     *  block, process it, and then continue padding into a second
     *  block.
     */
    if (context->Message_Block_Index > 55)
    {
        context->Message_Block[context->Message_Block_Index++] = 0x80;
        while(context->Message_Block_Index < 64)
        {
            context->Message_Block[context->Message_Block_Index++] = 0;
        }

        SHA1ProcessMessageBlock(context);

        while(context->Message_Block_Index < 56)
        {
            context->Message_Block[context->Message_Block_Index++] = 0;
        }
    }
    else
    {
        context->Message_Block[context->Message_Block_Index++] = 0x80;
            while(context->Message_Block_Index < 56)
        {

            context->Message_Block[context->Message_Block_Index++] = 0;
        }
    }

    /*
     *  Store the message length as the last 8 octets
     */
    context->Message_Block[56] = context->Length_High >> 24;
    context->Message_Block[57] = context->Length_High >> 16;
    context->Message_Block[58] = context->Length_High >> 8;
    context->Message_Block[59] = context->Length_High;
    context->Message_Block[60] = context->Length_Low >> 24;
    context->Message_Block[61] = context->Length_Low >> 16;
    context->Message_Block[62] = context->Length_Low >> 8;
    context->Message_Block[63] = context->Length_Low;

    SHA1ProcessMessageBlock(context);
}

/*
 *  SHA1Input
 *
 *  Description:
 *      This function accepts an array of octets as the next portion
 *      of the message.
 *
 *  Parameters:
 *      context: [in/out]
 *          The SHA context to update
 *      message_array: [in]
 *          An array of characters representing the next portion of
 *          the message.
 *      length: [in]
 *          The length of the message in message_array
 *
 *  Returns:
 *      sha Error Code.
 *
 */
int SHA1Input(    SHA    *context,
                  const uint8_t  *message_array,
                  unsigned       length)
{
    if (!length)
    {
        return shaSuccess;
    }

    if (!context || !message_array)
    {
        return shaNull;
    }

    if (context->Computed)
    {
        context->Corrupted = shaStateError;

        return shaStateError;
    }

    if (context->Corrupted)
    {
         return context->Corrupted;
    }
    while(length-- && !context->Corrupted)
    {
    context->Message_Block[context->Message_Block_Index++] =
                    (*message_array & 0xFF);

    context->Length_Low += 8;
    if (context->Length_Low == 0)
    {
        context->Length_High++;
        if (context->Length_High == 0)
        {
            /* Message is too long */
            context->Corrupted = 1;
        }
    }

    if (context->Message_Block_Index == 64)
    {
        SHA1ProcessMessageBlock(context);
    }

    message_array++;
    }

    return shaSuccess;
}

/*
 *  SHA1Result
 *
 *  Description:
 *      This function will return the 160-bit message digest into the
 *      Message_Digest array  provided by the caller.
 *      NOTE: The first octet of hash is stored in the 0th element,
 *            the last octet of hash in the 19th element.
 *
 *  Parameters:
 *      context: [in/out]
 *          The context to use to calculate the SHA-1 hash.
 *      Message_Digest: [out]
 *          Where the digest is returned.
 *
 *  Returns:
 *      sha Error Code.
 *
 */
int SHA1Result( SHA *context,
                uint8_t Message_Digest[SHA1HashSize])
{
    int i;

    if (!context || !Message_Digest)
    {
        return shaNull;
    }

    if (context->Corrupted)
    {
        return context->Corrupted;
    }

    if (!context->Computed)
    {
        SHA1PadMessage(context);
        for(i=0; i<64; ++i)
        {
            /* message may be sensitive, clear it out */
            context->Message_Block[i] = 0;
        }
        context->Length_Low = 0;    /* and clear length */
        context->Length_High = 0;
        context->Computed = 1;

    }

    for(i = 0; i < SHA1HashSize; ++i)
    {
        Message_Digest[i] = context->Intermediate_Hash[i>>2]
                            >> 8 * ( 3 - ( i & 0x03 ) );
    }

    return shaSuccess;
}

/*
 *  Cipher
 *
 *  Description:
 *      This funtion will take a string as an input following with four parameters.
 *      It will done a Caeser Cipher but not with an ordinary way. The Funtion
 *      will be consisit of a three coated lock which make its attacking complexity much harder.
 *            .
 *
 *  Parameters:
 *      text: [in/out]
 *          The text use to calculate the Caeser Cipher.
 *      move:[int]
 *          An integer which tell the number of shift in a text.
 *      time:[int]
 *          An integer on which the loop of shift will be run
 *      difference:[int]
 *           An integer which changes the shift value when times loop ends
 *      len:[int]
 *            The size of the particular string
 *
 *  Returns:
 *      Encrypted Text.
 *
 */

string Cipher(string text,int move,int times, int difference,int len)
{
    cout << "\nCiphering in Process...";
    Sleep(500);

    //system("cls");
    int j=0,i=0;
    int shift;
    while (j < len)
    {
                        if(text[j] == 32)
                                {
                                    text[j] = text[j];
                                }

                                j++;
    }

                            shift=move;

                            while (i < len)
                            {
                                for(int t=times;t>0;t--){

                                                                    text[i] = toupper(text[i]);
                                                                    text[i] = text[i] + shift;

                                                                    if (text[i] - shift == 32)
                                                                    {
                                                                        text[i] = text[i] - shift;
                                                                    }

                                                                    else if(
                                                                            ((text[i] - shift > 31) && (text[i] - shift < 65)
                                                                            || ((text[i] - shift > 90) && (text[i] - shift < 97))
                                                                            || ((text[i] - shift > 122) && (text[i] - shift < 128)))
                                                                            )
                                                                            {
                                                                                text[i] = text[i] - shift;
                                                                            }

                                                                    else if (text[i] > 90)
                                                                    {
                                                                        if (text[i] == 32 + shift)
                                                                        {
                                                                            text[i] = text[i] - shift;
                                                                        }
                                                                        else
                                                                        {
                                                                            text[i] = (text[i] - 26);
                                                                        }
                                                                    }
                                                                    i++;

                                         }


                            if(shift!=difference)
                            shift=difference;
                            else if(shift!=move)
                            shift=move;



                            }

return text;
}


/*
 *  De-Cipher
 *
 *  Description:
 *      This funtion will take a string as an input following with four parameters.
 *      The Funtion Decrypt the data with the same four digit code as described in Cipher Text.      .
 *
 *  Parameters:
 *      text: [in/out]
 *          The text to use to calculate the Caeser Cipher Decrypt.
 *      move:[int]
 *          An integer which tell the number of shift in a text.
 *      time:[int]
 *          An integer on which the loop of shift will be run
 *      difference:[int]
 *           An integer which changes the shift value when times loop ends
 *      len:[int]
 *            The size of the particular string
 *
 *  Returns:
 *      Decrypted Text.
 *
 */

string De_Cipher(string text,int move,int times, int difference,int len)
{

    cout<<"De-Ciphering in Process"<<endl;
    Sleep(430);
    int j=0,i=0,counter=0;
    int shift;
    while (j < len)
    {
                        if(text[j] == 32)
                                {
                                    text[j] = text[j];
                                }

                                j++;
    }

                            shift=move;

                            while (i < len)
                            {
                                for(int t=times;t>0;t--){

                                                                    text[i] = toupper(text[i]);
                                                                    text[i] = text[i] - shift;

                                                                    if (text[i] + shift == 32)
                                                                    {
                                                                        text[i] = text[i] + shift;
                                                                    }

                                                                    else if(
                                                                            ((text[i] + shift > 31) && (text[i] + shift < 65)
                                                                            || ((text[i] + shift > 90) && (text[i] + shift < 97))
                                                                            || ((text[i] + shift > 122) && (text[i] + shift < 128)))
                                                                            )
                                                                            {
                                                                                text[i] = text[i] + shift;
                                                                            }

                                                                    else if (text[i] > 90)
                                                                    {
                                                                        if (text[i] == 32 - shift)
                                                                        {
                                                                            text[i] = text[i] + shift;
                                                                        }
                                                                        else
                                                                        {
                                                                            text[i] = (text[i] + 26);
                                                                        }
                                                                    }
                                                                    i++;
                                                        }

                            if(shift!=difference)
                            shift=difference;
                            else if(shift!=move)
                            shift=move;

                            }

return text;
}
/*
 *  Cipher
 *
 *  Description:
 *      This funtion will take a character as an input following with one parameters.
 *      It will done a Caeser Cipher but not with the shift defined.
 *
 *  Parameters:
 *      character: [in/out]
 *          The character array use to calculate the Caeser Cipher.
 *      shift:[int]
 *          An integer which tell the number of shift in a text.
 *
 *      Returns:
 *          Encrypted Character.
 *
 */
char Cipher(char text,int shift)
{

            int j=0,i=0;
            if(text== 32)
                                {
                                    text= text;
                                    return text;
                                }



                                                                    if (text - shift == 32)
                                                                    {
                                                                        text = text - shift;

                                                                   }

                                                                    else if((text - shift >= 31) && (text - shift <= 65))
                                                                            text=text-shift;
                                                                    else if  ((text - shift >65 && text-shift<=90))
                                                                            text=text-shift;
                                                                    else if ((text - shift > 90 && text-shift <=122))
                                                                            text=text-shift;
                                                                    else if(text - shift > 122)
                                                                            text=text-shift;

return text;
}

/*
 *  De-Cipher
 *
 *  Description:
 *      This funtion will take a character as an input following with one parameters.
 *      It will done a Caeser Cipher but not with the shift defined.
 *
 *  Parameters:
 *      character: [in/out]
 *          The character array use to calculate the Caeser Cipher.
 *      shift:[int]
 *          An integer which tell the number of shift in a text.
 *
 *      Returns:
 *          De-crypted Character.
 *
 */
char De_Cipher(char text,int shift)
{
    int j=0,i=0,counter=0;
                        if(text == 32)
                                {
                                    text = text;
                                    return text;
                                }

                                                                    if (text + shift == 32)
                                                                    {
                                                                        text = text + shift;
                                                                    }

                                                                    else if((text + shift >= 31) && (text + shift  <= 65))
                                                                            text=text+shift;
                                                                    else if  ((text + shift >65 && text + shift<=90))
                                                                            text=text+shift;
                                                                    else if ((text + shift > 90 && text + shift <= 122))
                                                                            text=text+shift;
                                                                    else if(text + shift > 122)
                                                                            text=text+shift;
return text;
}

/*
 *  Cipher
 *
 *  Description:
 *            .This funtion will take an integer input, this integer came when our uint_8 bit hash conerted into decimal.
                The funtion will convert this decimal into a defined format of ASCHII
 *
 *  Parameters:
 *      integer: [in/out]
 *          An integer derived from HEX conversion.
 *
 *      Returns:
 *          Encrypted ASCHII Character.
 *
 */
char Cipher(int k)
{
    char a;
    int i=0;
    if(k>127)
    k=k%127;
    if(k<47)
    {
        i=47-k;
        k=i+47;
    }
    a= static_cast<int>(k);
    return a;
}

/*
 *  De-Cipher
 *
 *  Description:
 *            This funtion will take an integer input, this integer came when our uint_8 bit hash covnerted into decimal.
                The funtion will convert this decimal into a defined format of ASCHII
 *
 *  Parameters:
 *      integer: [in/out]
 *          An integer derived from HEX conversion.
 *
 *      Returns:
 *          De-crypted ASCHII Character.
 *
 */
char De_cipher(int k)
{
    char a;
    int i=0;
    if(k<47)
    {
        i=47+k;
        k=i-47;
    }
    a = static_cast<int>(k);
return a;
}
/*
 * ReadFromFile
 *
 * Description:
 *              This funton will take an object of ifstream and create a file of the said name
 * Parameter:
 *
 *   ifstream object
 *
 */
  void ReadFromFile(ifstream &infile)

{

        char FileName[20];

        cout<<"Enter the Name of your File:- ";
        cin>>FileName;
        cout<<"Opening the File";
        int i=0;

        while(i<5)
       {
            cout<<".";
            Sleep(300);
            i++;
        }

       infile.open(FileName);

}


int main()
{
/************************************************Data*************************************/
    SHA sha;//object of class
    /////////////////////Filing objects/////////////////////////////
    ifstream infile;
    ofstream outfileCipher;
    ofstream outfileDecipher;
    ofstream outfileT;
    ofstream outfileFinal;

    //FILE *fileout;
    //fileout = fopen("Signature.txt","a+");
    outfileCipher.open("Cipher.txt");
    outfileDecipher.open("De-Cipher.txt");
    outfileT.open("Signature.txt");
    infile.open("Cipher.txt");
    outfileFinal.open("Final Signature.txt");
    /////////////////////////////////////////////////////////////////
    int i=0, j=0, err=0,move=0,times=0,difference=0,length=0,shift=0;
    int SizeOfOriginalText=0;
    string Cipher_hash;
    string DeCipherText;
    int ConvertInInteger[40];
    char CipheredHash[40];
    char HashWithName[40];
    char name[10];
    string CipheredOfOriginalText;
    uint8_t Message_Digest[20];//unsigned integer of 8 bit, in short an unsigned character where we store our Hash
    int PrivateKey=133583;// Random Prime Number
    int PublicKey=66791;// 2*p+1
/*************************************************************************************************/
    char *testarray[] ={ "This is the sample text to test the Hashing Algorithm" };//test character array
    SizeOfOriginalText=strlen(*testarray);//storing the size of original text
    char OriginalText[SizeOfOriginalText];//character array of original text
/*************************************Converting Array Pointer into String************************/
    strcpy(OriginalText,*testarray);//Copying Character bits into string
    string Cipher_text(OriginalText);//Original text has been converted into String
/*********************************Displaying the Original Text***********************************/
    cout<<endl;
    cout<<"Following is your Text:-"<<endl;
    cout<<"**********************************************************************"<<endl;
    cout<<OriginalText<<endl;
    //outfileO<<OriginalText;
    //outfileO<<endl;
    cout<<"**********************************************************************"<<endl;
    cout<<endl;

/************************************************************************************************/
    cout<<"Press Any Key to Cipher Your Text";
    _getch();
     time_t Time = time(0);   // get time now
    struct tm * now = localtime( & Time );
    int Year,Month,Day,Hour,Min;
    Year=(now->tm_year + 1900);
    Month=(now->tm_mon + 1);
    Day=  now->tm_mday;
    Hour=now->tm_hour;
    Min=now->tm_min;
/*******************************Ciphering The Original Text*************************************/

    cout<<endl;
    cout<<"-------Enter a 3 Digit Code to Cipher Your Text (With Space)---------"<<endl;
    cin>>move;
    cin>>times;
    cin>>difference;
    CipheredOfOriginalText= Cipher(Cipher_text,move,times,difference,SizeOfOriginalText);
    cout<<endl;
    cout<<"Cipher Text:-"<<endl;
    cout<<"**********************************************************************"<<endl;
    cout<<CipheredOfOriginalText<<endl;
    outfileCipher<<CipheredOfOriginalText<<endl;
    cout<<"**********************************************************************"<<endl;
    char TIME[5];
    TIME[1]=static_cast<char>(Month);
    TIME[2]=static_cast<char>(Day);
    TIME[3]=static_cast<char>(Hour);
    TIME[4]=static_cast<char>(Min);
    for(i=0;i<5;i++)
    outfileCipher<<TIME[i];

    outfileCipher<<endl;
    cout<<"Successfully Ciphered"<<endl;
/************************************************************************************************/


/*******************************Producing the Hash of Original Text******************************/

    cout<<"Press Enter to Produce a Secure Hash of Your Text";
    _getch();
    cout<<endl;
    cout<<"Hashing";
    for(int i=0;i<5;i++)
    {
        cout<<".";
        Sleep(500);
    }
    cout<<endl;



    fflush(stdin);
    /*-----------------SHA-1 Algorithm Implementation----------------------*/
    for(j = 0; j < 1; ++j)
    {
        //printf( "\nTest %d:'%s'\n",j+1,testarray[j]);
        cout<<"Your Hash for the Text is"<<endl;
        cout<<"**********************************************************************"<<endl;
        err = SHA1Reset(&sha);
        if (err)
        {
            fprintf(stderr, "SHA1Reset Error %d.\n", err );
            break;    // out of for j loop
        }

        for(i = 0; i < 1; ++i)
        {

            err = SHA1Input(&sha,
                  (const unsigned char *) testarray[j],
                  strlen(testarray[j]));
            if (err)
            {
                    fprintf(stderr, "SHA1Input Error %d.\n", err );
                break;    /* out of for i loop */
            }
        }

        err = SHA1Result(&sha, Message_Digest);
        if (err)
        {
            fprintf(stderr,
            "SHA1Result Error %d, could not compute message digest.\n",
            err );
        }
        else
        {
            printf("\t");
            for(i = 0; i < 20 ; ++i)
            {
                Message_Digest[i];
                printf("%02X ",Message_Digest[i]);
                //fprintf(fileout, "%02X ",Message_Digest[i] );
            }
            cout<<endl;
            cout<<"**********************************************************************"<<endl;

        }
    }

    /*-----------------SHA-1 Algorithm Implementation End----------------------*/


/*******************************Producing the Hash of Original Text******************************/



/*******************************Attaching Name with Hash*****************************************/

        cout<<"Please input Your Name: "<<endl;
        gets(name);
        length=strlen(name);
        cout<<endl;
        cout<<"Attaching Your Name with Hash";
        for(int i=0;i<3;i++)
         {
             cout<<".";
             Sleep(400);
         }

        for(i = 0; i < 20 ; ++i)
            {
                ConvertInInteger[i]=static_cast<int>(Message_Digest[i]);//Converting Hash Bits equivalent Decimal into integer Array
            }
        for(int b=0;b<length;b++)
            {
                            ConvertInInteger[i+b+1]=static_cast<int>(name[b]);//Inserting Name String integer Value into Integer Array

            }

        cout<<endl;


/************************************************************************************************/



/*******************************Converting the Integers into ASCHII******************************/
        cout<<"Hash With Name: "<<endl;

        for(int i=0;i<20+length+1;i++)
            {

            HashWithName[i]=Cipher(ConvertInInteger[i]);
            cout<<HashWithName[i]<<" ";
            outfileT<<HashWithName[i]<<" ";
            }
            cout<<endl;
/************************************************************************************************/

        cout<<"Successfully Attached the Name"<<endl;
        cout<<"Please Enter to Cipher Your Hash"<<endl;
        _getch();

//        char Cipher_hash[30];
/************************************Ciphering The Hash********************************************/
        shift=0;
        times=0;
        difference=0;
        cout<<"-------Enter a 3 Digit Code to Cipher Your Hash (With Space)---------"<<endl;
        cin>>shift;
        cin>>times;
        cin>>difference;
        cout<<endl;

            for(int i=0;i<20+length+1;i++)//20 is the length of Digest, length is size of name and +1 is for space null terminator
            {
                CipheredHash[i]=Cipher(HashWithName[i],shift);//Ciphering the Hash
                times--;
                if(times==0)
                {
                    shift=difference+i;
                }
            }
            for(int i=0;i<20+length+1;i++)
            {
                cout<<CipheredHash[i]<<" ";
               // outfileT<<CipheredHash[i]<<" ";
            }
            outfileT<<endl;
            cout<<endl;
/************************************************************************************************/

/***************************************Private Key Encryption*****************************************/

            for(int i=0;i<20+length+1;i++)
            CipheredHash[i]=static_cast<int>(CipheredHash[i])+PrivateKey;

            outfileFinal<<endl;
            cout<<endl;
            cout<<"**********************************************************************"<<endl;

            cout<<"Result After Private Key"<<endl;
            cout<<"**********************************************************************"<<endl;

            for(int i=0;i<20+length+1;i++)
            {
                cout<<CipheredHash[i]<<" ";
                outfileFinal<<CipheredHash[i]<<" ";
            }
            cout<<endl;
            outfileFinal<<endl;
/**********************************************************************************************************/
cout<<"Recievers End Sarting";
for(i=0;i<5;i++)
{
    Sleep(400);
    cout<<". ";
}
cout<<endl;
/*******************************Public Key Decryption******************************************************/

            for(int i=0;i<20+length+1;i++)
            CipheredHash[i]=static_cast<int>(CipheredHash[i])-(2*PublicKey+1);

            cout<<endl;
            cout<<"**********************************************************************"<<endl;

            cout<<"Result After Public Key"<<endl;
            cout<<"**********************************************************************"<<endl;

            for(int i=0;i<20+length+1;i++)
            {
                cout<<CipheredHash[i]<<" ";
            }
            cout<<endl;


/************************************************************************************************/

/*****************************De-Ciphering The Hash**********************************************/

        shift=0;
        times=0;
        difference=0;
        cout<<"-------Enter a 3 Digit Code to De-Cipher Your Hash (With Space)---------"<<endl;
        cin>>shift;
        cin>>times;
        cin>>difference;
        cout<<endl;

            for(int i=0;i<20+length+1;i++)
            {
                CipheredHash[i]=De_Cipher(CipheredHash[i],shift);
                times--;
                if(times==0)
                {
                    shift=difference+i;
                }


            }

            for(int i=0;i<20+length+1;i++)
            {
                cout<<CipheredHash[i]<<" ";

            }

/******************************************************************************************************/

/*******************************De-Ciphering The Original Text*************************************/
    move=0;
    difference=0;
    times=0;
    cout<<endl;
    cout<<"-------Enter a 3 Digit Code to De-Cipher Your Text (With Space)---------"<<endl;
    cin>>move;
    cin>>times;
    cin>>difference;
    DeCipherText= De_Cipher(CipheredOfOriginalText,move,times,difference,SizeOfOriginalText);
    cout<<endl;
    cout<<"De-Cipher Text:-"<<endl;
    cout<<"**********************************************************************"<<endl;
    cout<<DeCipherText<<endl;
    outfileDecipher<<DeCipherText<<endl;
    cout<<"**********************************************************************"<<endl;
    Month=static_cast<int>(TIME[1]);
    Day=static_cast<int>(TIME[2]);
    Hour=static_cast<int>(TIME[3]);
    Min=static_cast<int>(TIME[4]);

    outfileDecipher<<Month<<" "<<Day<<" "<<Hour<<":"<<Min;
    outfileDecipher<<endl;
    cout<<"Successfully Ciphered"<<endl;
/************************************************************************************************/

outfileT.close();
    return 0;
}
