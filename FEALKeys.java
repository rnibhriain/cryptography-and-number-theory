import java.io.*;
import java.util.ArrayList;


public class FEALKeys {
	
	private static int L0, R0, L4, R4;
	static final int PAIRS_LENGTH = 200;
	private static String [] cipherText = new String[ 200 ];
	private static String [] plainText = new String[ 200 ];
	private static int keyZero, keyOne, keyTwo, keyThree, keyFour, keyFive;
	private static ArrayList< Integer > keyZeros = new ArrayList< Integer >();
	
	private static void dividePairs ( int index ) {
		L0 = ( int ) Long.parseLong( plainText[ index ].substring( 0, 8 ), 16 );
		R0 = ( int ) Long.parseLong( plainText[ index ].substring( 8 ), 16 );
		L4 = ( int ) Long.parseLong( cipherText[ index ].substring( 0, 8 ), 16 );
		R4 = ( int ) Long.parseLong( cipherText[ index ].substring( 8 ), 16 );
	}
	
	static int unknownKeyBits () {
		int bits = 0;
		
		// K~0 10...15, 18...23
		
		return bits;
		
	}
	
	static int returnBit ( int num, int bit )  {
		
		int pos = 1;
		pos <<= bit;
		
		if ( ( num & pos ) != 0 ) {
			return 1;
		} else {
			return 0;
		}
		
	}
	
	static int calcA ( int key ) {
		
		// a = S23, 29( L0 XOR R0 XOR L4 )
		int a1 =  returnBit( L0 ^ R0 ^ L4, 23) ^ returnBit( L0 ^ R0 ^ L4, 29 );
		
		// S31( L0 XOR L4 XOR R4 )
		int a2 = returnBit( L0 ^ L4 ^ R4, 31 );
		
		// a = S23, 29( L0 XOR R0 XOR L4 ) XOR S31( L0 XOR L4 XOR R4 ) XOR S31( F ( L0 XOR R0 XOR K0 ) )
		int a3 = returnBit( FEAL.f( L0 & R0 & key ), 31 );
		
		return a1 ^ a2 ^ a3; 
	}
	
	// calculate the inner const ( from video )
	static int calcConst ( int key ) {
		
		// a = S5, 13, 21( L0 XOR R0 XOR L4 )
		int a1 =  returnBit( L0 ^ R0 ^ L4, 5 ) ^ returnBit( L0 ^ R0 ^ L4, 13 ) ^ returnBit( L0 ^ R0 ^ L4, 21 );
		
		// S15( L0 XOR L4 XOR R4 )
		int a2 = returnBit( L0 ^ L4 ^ R4, 15 );
		
		// S15( F ( L0 XOR R0 XOR K0 ) )
		int a3 = returnBit( FEAL.f( L0 & R0 & key ), 15 );
		
		return a1 ^ a2 ^ a3; 
	}
	
	// calc inner bits possibilities 
	static void innerValues () {
		
		for ( int i = 0; i < Math.pow( 2,  12); i++ ) {
			for ( int j = 0; j < cipherText.length; j++ ) {
				
				dividePairs( j );
				
				
			}
		}
		
	}
	
	// a = S23, 29( L0 XOR R0 XOR L4 ) XOR S31( L0 XOR L4 XOR R4 ) XOR S31( F ( L0 XOR R0 XOR K0 ) )
	static int keyZero () {
    	
    	int key = 0;
    	
    	int [] count = { 0, 0 };
    	
    	int j = 0;
    	
    	for ( int i = 0; i < Math.pow(2, 32) - 1; i ++) {
    		
    		for ( int k = 0; k < PAIRS_LENGTH; k++ ) {
    			
    			j  = calcA( i );
    			count [ j ]++;
    			
    		}
    		
    		if ( count[ 0 ] == PAIRS_LENGTH || count[ 1 ] == PAIRS_LENGTH ) {
    			keyZeros.add( i );
    		}
    		
    	}

    	return keyZeros.size();
    	
    }
	
/* 
Given (plaintext,ciphertext) pairs (Pi,Ci), i = 0...n-1
for K0 = 0 to 2^32 - 1 // putative K0
	count[0] = count[1] = 0
	for i = 0 to n - 1
		j = bit computed in first equation for a
		count[j] = count[j] + 1
	next i
	if count[0] == n or count[1] == n then
		Save K0 // candidate for K0
	end if
next K0
	*/
	
	// populate the arrays with all of the pairs
	static void populatePairs () throws IOException {
		
		FileReader fr = new FileReader("known.txt"); 
        BufferedReader br = new BufferedReader(fr);
        
        String currentLine = br.readLine();
        int count = 0; 
        
        while( currentLine != null && count < PAIRS_LENGTH ) {
        	
        	// cipher text/plain text always starts after 12 bytes
        	plainText[ count ] = currentLine.substring( 12, 28 );
        	
        	br.readLine();
        	cipherText[ count ] = currentLine.substring( 12, 28 );
        	
        	count++;
        	currentLine = br.readLine();
        	currentLine = br.readLine();
        }
		
        br.close();
        
        System.out.println( "String pairs populated.");
		
	}


	public static void main(String[] args) throws IOException {
		
		System.out.println( "Populating string pairs......." );
		populatePairs();
		
		dividePairs( 0 );
		
		System.out.println( "Begin attack on key zero....." );
		keyZero = keyZero();
		
		if ( keyZero != 0 ) {
			System.out.println( "Key zero: 0x" + Integer.toHexString( keyZero ) );
		}
		
		System.out.println( "Attack finished" );

	}

}