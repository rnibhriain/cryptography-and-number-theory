import java.io.*;

public class FEALKeys {

	private static int L0, R0, L4, R4;
	static final int PAIRS_LENGTH = 200;
	private static String [] cipherText = new String[ PAIRS_LENGTH ];
	private static String [] plainText = new String[ PAIRS_LENGTH ];
	private static int keyZero = -1, keyOne = -1, keyTwo = -1, keyThree = -1, keyFour = -1, keyFive = -1;

	private static void dividePairs ( int index ) {
		L0 = ( int ) Long.parseLong( plainText[ index ].substring( 0, 8 ), 16 );
		R0 = ( int ) Long.parseLong( plainText[ index ].substring( 8 ), 16 );
		L4 = ( int ) Long.parseLong( cipherText[ index ].substring( 0, 8 ), 16 );
		R4 = ( int ) Long.parseLong( cipherText[ index ].substring( 8 ), 16 );
	}

	// return whether bit is 1 or 0
	private static int returnBit ( int num, int bit )  {

		int pos = 1;
		pos <<= bit;

		if ( ( num & pos ) != 0 ) {
			return 1;
		} else {
			return 0;
		}

	}

	// organise bits into 10..15 & 18..23
	// professor says this should b << 10 and << 8 instead of 12 and 10 but i'm unconvinced
	private static int inner12Bits ( int key ) {
		return ( ( key & ( 0x3f << 6 ) ) << 10 ) | ( ( key & 0x3F ) << 8 );
	}

	// calculate the inner const ( from video )
	private static int calcInnerConstK0 ( int key ) {

		// a = S5, 13, 21( L0 XOR R0 XOR L4 )
		int a1 =  returnBit( L0 ^ R0 ^ L4, 5 ) ^ returnBit( L0 ^ R0 ^ L4, 13 ) ^ returnBit( L0 ^ R0 ^ L4, 21 );

		// S15( L0 XOR L4 XOR R4 )
		int a2 = returnBit( L0 ^ L4 ^ R4, 15 );

		// S15( F ( L0 XOR R0 XOR K0 ) )
		int a3 = returnBit( FEAL.f( L0 ^ R0 ^ key ), 15 );

		return a1 ^ a2 ^ a3; 
	}

	// calc inner bits possibilities 10..15 & 18..23 
	private static int innerValuesK0 () {

		int j = 0;

		boolean moveOn = false;

		// optimised version of the original function - move on if its not equal to the first result
		for ( int i = 0; i < Math.pow(2, 12); i++ ) {

			int key = inner12Bits( i );
			dividePairs( 0 );
			j = calcInnerConstK0( key );

			int k = 0;
			for ( k = 1; k < PAIRS_LENGTH; k++ ) {

				dividePairs( k );

				if ( j != calcInnerConstK0( key ) ) {

					moveOn = true;
					//System.out.println( "hello " + Integer.toBinaryString( key ) + " and " + k );
					k = PAIRS_LENGTH;

				}

			}

			if ( !moveOn ) {
				System.out.println( "DONE INNER BITS: " + key );
				System.out.println( "got here" );
				return key;
			} else {
				moveOn = false;
			}

		}
		
		System.out.println( "FAILED INNER BITS " );
		return 0;

	}

	// calculate the outer const ** TODO
	private static int calcOuterConstK0 ( int key ) {

		// S13(L0 ⊕ R0 ⊕ L4)
		int a1 = returnBit(L0^R0^L4, 13);

		// S7,15,23,31(L0 ⊕ L4 ⊕ R4)
		int a2 = returnBit(L0^L4^R4, 7)^returnBit(L0^L4^R4, 15)^returnBit(L0^L4^R4, 23)^returnBit(L0^L4^R4, 31);

		// S7,15,23,31 F(L0 ⊕ R0 ⊕ K0)
		int y0 = FEAL.f(L0^R0^key);
		int a3 = returnBit(y0, 7)^returnBit(y0, 15)^returnBit(y0, 23)^returnBit(y0, 31);

		return a1^a2^a3;
	}

	// organise bits into 0..9 & 16..17 & 24..31
	private static int outer20Bits ( int key ) {
		//return (((key >> 6) & 0x3F) << 16) + ((key & 0x3F) << 8) ;
		return ( ( key & 0x7F800 ) << 11 ) | ( ( key & 0x600 ) << 6 ) | ( key & 0x1FF );
	}

	private static int outerValuesK0 ( int innerBits ) {

		int j = 0;

		boolean moveOn = false;

		// optimised version of the original function - move on if its not equal to the first result
		for ( int i = 0; i < Math.pow( 2, 20 ); i++ ) {

			int key = outer20Bits( i );
			key |= innerBits;
			dividePairs( 0 );
			j = calcOuterConstK0( key );

			int k = 0;
			for ( k = 1; k < PAIRS_LENGTH; k++ ) {

				dividePairs( k );

				if ( j != calcOuterConstK0( key ) ) {

					moveOn = true;
					//System.out.println( "hello " + Integer.toBinaryString( key ) + " and " + k );
					k = PAIRS_LENGTH;

				}

			}

			if ( !moveOn ) {
				System.out.println( "FOUND OUTER BITS: " );
				System.out.println( "got here" );
				return key;
			} else {
				moveOn = false;
			}

		}

		System.out.println( "FAILED OUTER BITS " );
		return -1;

	}

	// a = S23, 29( L0 XOR R0 XOR L4 ) XOR S31( L0 XOR L4 XOR R4 ) XOR S31( F ( L0 XOR R0 XOR K0 ) )
	private static int keyZero () {
		System.out.println( "Begin attack on key zero....." );

		return outerValuesK0( innerValuesK0() );

	}


	// populate the arrays with all of the pairs
	private static void populatePairs () throws IOException {

		FileReader fr = new FileReader("known.txt"); 
		BufferedReader br = new BufferedReader(fr);

		String currentLine = br.readLine();
		int count = 0; 

		while( currentLine != null && count < PAIRS_LENGTH ) {

			// cipher text/plain text always starts after 12 bytes
			plainText[ count ] = currentLine.substring( 12 );

			currentLine = br.readLine();
			
			cipherText[ count ] = currentLine.substring( 12 );

			count++;
			br.readLine();
			currentLine = br.readLine();
		}

		br.close();

		System.out.println( "String pairs populated.");

	}


	public static void main(String[] args) throws IOException {

		System.out.println( "Populating string pairs......." );
		populatePairs();

		keyZero = keyZero();

		if ( keyZero != -1 && keyOne != -1 && keyTwo != -1 && keyThree != -1 && keyFour != -1 && keyFive != -1 ) {

			System.out.println( "Key zero: 0x" + Integer.toHexString( keyZero ) );
			System.out.println( "Key one: 0x" + Integer.toHexString( keyOne ) );
			System.out.println( "Key two: 0x" + Integer.toHexString( keyTwo ) );
			System.out.println( "Key three: 0x" + Integer.toHexString( keyThree ) );
			System.out.println( "Key four: 0x" + Integer.toHexString( keyFour ) );
			System.out.println( "Key five: 0x" + Integer.toHexString( keyFive ) );

			System.out.println( "Attack finished" );
			
		} else {
			System.out.println( "ATTACK FAILED" );
		}	

	}

}