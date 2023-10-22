import java.io.*;
import java.util.ArrayList;


public class FEALKeys {
	
	private static int L0, R0, L4, R4;
	static final int PAIRS_LENGTH = 200;
	private static String [] cipherText = new String[ PAIRS_LENGTH ];
	private static String [] plainText = new String[ PAIRS_LENGTH ];
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
	static int calcConstK0 ( int key ) {
		
		// a = S5, 13, 21( L0 XOR R0 XOR L4 )
		int a1 =  returnBit( L0 ^ R0 ^ L4, 5 ) ^ returnBit( L0 ^ R0 ^ L4, 13 ) ^ returnBit( L0 ^ R0 ^ L4, 21 );
		
		// S15( L0 XOR L4 XOR R4 )
		int a2 = returnBit( L0 ^ L4 ^ R4, 15 );
		
		// S15( F ( L0 XOR R0 XOR K0 ) )
		int a3 = returnBit( FEAL.f( L0 ^ R0 ^ key ), 15 );
		
		return a1 ^ a2 ^ a3; 
	}
	
	// organise bits into 10..15 & 18..23
	static int inner12Bits ( int key ) {
		return ( ( key & ( 0x3f << 6 ) ) << 12 ) | ( ( key & 0x3F ) << 10 );
	}
	
	// calc inner bits possibilities 10..15 & 18..23
	static void innerValues () {
    	
    	int j = 0;
    	
    	boolean moveOn = false;
		
    	// optimised version of the original function - move on if its not equal to the first result
		for ( int i = 0; i < 4096; i++ ) {
			
			int key = inner12Bits( i );
			
			dividePairs( 0 );
	    	j = calcConstK0( key );
			//System.out.println( "key: " + Integer.toHexString( key ));
			
			for ( int k = 1; k < PAIRS_LENGTH; k++ ) {
				
				dividePairs( k );
				
				if ( j != calcConstK0( key ) ) {
					moveOn = true;
					System.out.println( "hello" + i + " and " + k );
					k = PAIRS_LENGTH;
				}
				
			}
			
			if ( !moveOn ) {
				keyZeros.add( i );
				System.out.println( "got here innit" );
			} else {
				moveOn = false;
			}
			
		}
		
		System.out.println( "DONE: " + keyZeros.size() );
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
		
		innerValues();
		
		System.out.println( "Begin attack on key zero....." );
		//keyZero = keyZero();
		
		if ( keyZero != 0 ) {
			System.out.println( "Key zero: 0x" + Integer.toHexString( keyZero ) );
		}
		
		System.out.println( "Attack finished" );

	}

}