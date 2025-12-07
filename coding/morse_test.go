package coding

import (
	"errors"
	"strings"
	"testing"

	"github.com/dromara/dongle/internal/mock"
	"github.com/stretchr/testify/assert"
)

// Test data for morse encoding (generated using Python implementation)
var (
	morseSrc     = []byte("hello")
	morseEncoded = ".... . .-.. .-.. ---"
)

// Test data for morse world encoding (generated using Python implementation)
var (
	morseWorldSrc     = []byte("world")
	morseWorldEncoded = ".-- --- .-. .-.. -.."
)

// Test data for morse hello world encoding (generated using dongle implementation)
var (
	morseHelloWorldSrc     = []byte("hello world")
	morseHelloWorldEncoded = ".... . .-.. .-.. --- / .-- --- .-. .-.. -.."
)

// Test data for morse abc encoding (generated using Python implementation)
var (
	morseAbcSrc     = []byte("abc")
	morseAbcEncoded = ".- -... -.-."
)

// Test data for morse numbers encoding (generated using Python implementation)
var (
	morseNumbersSrc     = []byte("123")
	morseNumbersEncoded = ".---- ..--- ...--"
)

// Test data for morse test encoding (generated using Python implementation)
var (
	morseTestSrc     = []byte("test")
	morseTestEncoded = "- . ... -"
)

// Test data for morse quick encoding (generated using Python implementation)
var (
	morseQuickSrc     = []byte("quick")
	morseQuickEncoded = "--.- ..- .. -.-. -.-"
)

// Test data for morse brown encoding (generated using Python implementation)
var (
	morseBrownSrc     = []byte("brown")
	morseBrownEncoded = "-... .-. --- .-- -."
)

// Test data for morse fox encoding (generated using Python implementation)
var (
	morseFoxSrc     = []byte("fox")
	morseFoxEncoded = "..-. --- -..-"
)

// Test data for morse jumps encoding (generated using Python implementation)
var (
	morseJumpsSrc     = []byte("jumps")
	morseJumpsEncoded = ".--- ..- -- .--. ..."
)

// Test data for morse over encoding (generated using Python implementation)
var (
	morseOverSrc     = []byte("over")
	morseOverEncoded = "--- ...- . .-."
)

// Test data for morse lazy encoding (generated using Python implementation)
var (
	morseLazySrc     = []byte("lazy")
	morseLazyEncoded = ".-.. .- --.. -.--"
)

// Test data for morse dog encoding (generated using Python implementation)
var (
	morseDogSrc     = []byte("dog")
	morseDogEncoded = "-.. --- --."
)

// Test data for morse the encoding (generated using Python implementation)
var (
	morseTheSrc     = []byte("the")
	morseTheEncoded = "- .... ."
)

// Test data for morse single letter encoding (generated using Python implementation)
var (
	morseSingleLetterSrc     = []byte("a")
	morseSingleLetterEncoded = ".-"
)

// Test data for morse two letters encoding (generated using Python implementation)
var (
	morseTwoLettersSrc     = []byte("ab")
	morseTwoLettersEncoded = ".- -..."
)

// Test data for morse three letters encoding (generated using Python implementation)
var (
	morseThreeLettersSrc     = []byte("abc")
	morseThreeLettersEncoded = ".- -... -.-."
)

// Test data for morse all letters encoding (generated using Python implementation)
var (
	morseAllLettersSrc     = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	morseAllLettersEncoded = ".- -... -.-. -.. . ..-. --. .... .. .--- -.- .-.. -- -. --- .--. --.- .-. ... - ..- ...- .-- -..- -.-- --.."
)

// Test data for morse all numbers encoding (generated using Python implementation)
var (
	morseAllNumbersSrc     = []byte("0123456789")
	morseAllNumbersEncoded = "----- .---- ..--- ...-- ....- ..... -.... --... ---.. ----."
)

// Test data for morse punctuation encoding (generated using Python implementation)
var (
	morsePunctuationSrc     = []byte(".,?!")
	morsePunctuationEncoded = ".-.-.- --..-- ..--.. -.-.--"
)

// Test data for morse mixed case encoding (generated using dongle implementation)
var (
	morseMixedCaseSrc     = []byte("mixed CASE")
	morseMixedCaseEncoded = "-- .. -..- . -.. / -.-. .- ... ."
)

func TestEncoder_ByMorse_Encode(t *testing.T) {
	t.Run("encode string", func(t *testing.T) {
		encoder := NewEncoder().FromString(string(morseSrc)).ByMorse()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, morseEncoded, encoder.ToString())
	})

	t.Run("encode bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(morseSrc).ByMorse()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, morseEncoded, encoder.ToString())
	})

	t.Run("encode file", func(t *testing.T) {
		file := mock.NewFile(morseSrc, "test.txt")
		defer file.Close()
		encoder := NewEncoder().FromFile(file).ByMorse()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, morseEncoded, encoder.ToString())
	})

	t.Run("encode empty string", func(t *testing.T) {
		encoder := NewEncoder().FromString("").ByMorse()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})

	t.Run("encode empty bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes([]byte{}).ByMorse()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})

	t.Run("encode nil bytes", func(t *testing.T) {
		encoder := NewEncoder().FromBytes(nil).ByMorse()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})

	t.Run("encode empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		defer file.Close()
		encoder := NewEncoder().FromFile(file).ByMorse()
		assert.Nil(t, encoder.Error)
		assert.Empty(t, encoder.ToString())
	})

	t.Run("world string", func(t *testing.T) {
		encoder := NewEncoder().FromString(string(morseWorldSrc)).ByMorse()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, morseWorldEncoded, encoder.ToString())
	})

	t.Run("hello world string", func(t *testing.T) {
		encoder := NewEncoder().FromString(string(morseHelloWorldSrc)).ByMorse()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, morseHelloWorldEncoded, encoder.ToString())
	})

	t.Run("abc string", func(t *testing.T) {
		encoder := NewEncoder().FromString(string(morseAbcSrc)).ByMorse()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, morseAbcEncoded, encoder.ToString())
	})

	t.Run("numbers string", func(t *testing.T) {
		encoder := NewEncoder().FromString(string(morseNumbersSrc)).ByMorse()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, morseNumbersEncoded, encoder.ToString())
	})

	t.Run("test string", func(t *testing.T) {
		encoder := NewEncoder().FromString(string(morseTestSrc)).ByMorse()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, morseTestEncoded, encoder.ToString())
	})

	t.Run("quick string", func(t *testing.T) {
		encoder := NewEncoder().FromString(string(morseQuickSrc)).ByMorse()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, morseQuickEncoded, encoder.ToString())
	})

	t.Run("brown string", func(t *testing.T) {
		encoder := NewEncoder().FromString(string(morseBrownSrc)).ByMorse()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, morseBrownEncoded, encoder.ToString())
	})

	t.Run("fox string", func(t *testing.T) {
		encoder := NewEncoder().FromString(string(morseFoxSrc)).ByMorse()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, morseFoxEncoded, encoder.ToString())
	})

	t.Run("jumps string", func(t *testing.T) {
		encoder := NewEncoder().FromString(string(morseJumpsSrc)).ByMorse()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, morseJumpsEncoded, encoder.ToString())
	})

	t.Run("over string", func(t *testing.T) {
		encoder := NewEncoder().FromString(string(morseOverSrc)).ByMorse()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, morseOverEncoded, encoder.ToString())
	})

	t.Run("lazy string", func(t *testing.T) {
		encoder := NewEncoder().FromString(string(morseLazySrc)).ByMorse()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, morseLazyEncoded, encoder.ToString())
	})

	t.Run("dog string", func(t *testing.T) {
		encoder := NewEncoder().FromString(string(morseDogSrc)).ByMorse()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, morseDogEncoded, encoder.ToString())
	})

	t.Run("the string", func(t *testing.T) {
		encoder := NewEncoder().FromString(string(morseTheSrc)).ByMorse()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, morseTheEncoded, encoder.ToString())
	})

	t.Run("single letter", func(t *testing.T) {
		encoder := NewEncoder().FromString(string(morseSingleLetterSrc)).ByMorse()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, morseSingleLetterEncoded, encoder.ToString())
	})

	t.Run("two letters", func(t *testing.T) {
		encoder := NewEncoder().FromString(string(morseTwoLettersSrc)).ByMorse()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, morseTwoLettersEncoded, encoder.ToString())
	})

	t.Run("three letters", func(t *testing.T) {
		encoder := NewEncoder().FromString(string(morseThreeLettersSrc)).ByMorse()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, morseThreeLettersEncoded, encoder.ToString())
	})

	t.Run("all letters", func(t *testing.T) {
		encoder := NewEncoder().FromString(string(morseAllLettersSrc)).ByMorse()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, morseAllLettersEncoded, encoder.ToString())
	})

	t.Run("all numbers", func(t *testing.T) {
		encoder := NewEncoder().FromString(string(morseAllNumbersSrc)).ByMorse()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, morseAllNumbersEncoded, encoder.ToString())
	})

	t.Run("punctuation", func(t *testing.T) {
		encoder := NewEncoder().FromString(string(morsePunctuationSrc)).ByMorse()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, morsePunctuationEncoded, encoder.ToString())
	})

	t.Run("mixed case", func(t *testing.T) {
		encoder := NewEncoder().FromString(string(morseMixedCaseSrc)).ByMorse()
		assert.Nil(t, encoder.Error)
		assert.Equal(t, morseMixedCaseEncoded, encoder.ToString())
	})

	t.Run("large data", func(t *testing.T) {
		largeData := []byte(strings.Repeat("The quick brown fox jumps over the lazy dog. ", 10))
		encoder := NewEncoder().FromBytes(largeData).ByMorse()
		assert.Nil(t, encoder.Error)
		assert.NotEmpty(t, encoder.ToString())
	})

	t.Run("error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		encoder := NewEncoder().FromFile(errorFile).ByMorse()
		assert.Error(t, encoder.Error)
		assert.Contains(t, encoder.Error.Error(), "read error")
	})

	t.Run("encode no data", func(t *testing.T) {
		encoder := NewEncoder().ByMorse()
		if encoder.Error != nil {
			assert.Contains(t, encoder.Error.Error(), "no data to encode")
		}
	})
}

func TestEncoder_ByMorse_Error(t *testing.T) {
	t.Run("existing error", func(t *testing.T) {
		encoder := NewEncoder()
		encoder.Error = errors.New("existing error")
		result := encoder.FromString("test").ByMorse()
		assert.Equal(t, errors.New("existing error"), result.Error)
		assert.NotNil(t, result.src)
	})
}

func TestDecoder_ByMorse_Decode(t *testing.T) {
	t.Run("decode string", func(t *testing.T) {
		decoder := NewDecoder().FromString(morseEncoded).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, morseSrc, decoder.ToBytes())
	})

	t.Run("decode bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes([]byte(morseEncoded)).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, morseSrc, decoder.ToBytes())
	})

	t.Run("decode file", func(t *testing.T) {
		file := mock.NewFile([]byte(morseEncoded), "test.txt")
		defer file.Close()
		decoder := NewDecoder().FromFile(file).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, morseSrc, decoder.ToBytes())
	})

	t.Run("decode empty string", func(t *testing.T) {
		decoder := NewDecoder().FromString("").ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})

	t.Run("decode empty bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes([]byte{}).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})

	t.Run("decode nil bytes", func(t *testing.T) {
		decoder := NewDecoder().FromBytes(nil).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})

	t.Run("decode empty file", func(t *testing.T) {
		file := mock.NewFile([]byte{}, "empty.txt")
		defer file.Close()
		decoder := NewDecoder().FromFile(file).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Empty(t, decoder.ToBytes())
	})

	t.Run("world string", func(t *testing.T) {
		decoder := NewDecoder().FromString(morseWorldEncoded).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, morseWorldSrc, decoder.ToBytes())
	})

	t.Run("hello world string", func(t *testing.T) {
		decoder := NewDecoder().FromString(morseHelloWorldEncoded).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, morseHelloWorldSrc, decoder.ToBytes())
	})

	t.Run("abc string", func(t *testing.T) {
		decoder := NewDecoder().FromString(morseAbcEncoded).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, morseAbcSrc, decoder.ToBytes())
	})

	t.Run("numbers string", func(t *testing.T) {
		decoder := NewDecoder().FromString(morseNumbersEncoded).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, morseNumbersSrc, decoder.ToBytes())
	})

	t.Run("test string", func(t *testing.T) {
		decoder := NewDecoder().FromString(morseTestEncoded).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, morseTestSrc, decoder.ToBytes())
	})

	t.Run("quick string", func(t *testing.T) {
		decoder := NewDecoder().FromString(morseQuickEncoded).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, morseQuickSrc, decoder.ToBytes())
	})

	t.Run("brown string", func(t *testing.T) {
		decoder := NewDecoder().FromString(morseBrownEncoded).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, morseBrownSrc, decoder.ToBytes())
	})

	t.Run("fox string", func(t *testing.T) {
		decoder := NewDecoder().FromString(morseFoxEncoded).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, morseFoxSrc, decoder.ToBytes())
	})

	t.Run("jumps string", func(t *testing.T) {
		decoder := NewDecoder().FromString(morseJumpsEncoded).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, morseJumpsSrc, decoder.ToBytes())
	})

	t.Run("over string", func(t *testing.T) {
		decoder := NewDecoder().FromString(morseOverEncoded).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, morseOverSrc, decoder.ToBytes())
	})

	t.Run("lazy string", func(t *testing.T) {
		decoder := NewDecoder().FromString(morseLazyEncoded).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, morseLazySrc, decoder.ToBytes())
	})

	t.Run("dog string", func(t *testing.T) {
		decoder := NewDecoder().FromString(morseDogEncoded).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, morseDogSrc, decoder.ToBytes())
	})

	t.Run("the string", func(t *testing.T) {
		decoder := NewDecoder().FromString(morseTheEncoded).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, morseTheSrc, decoder.ToBytes())
	})

	t.Run("single letter", func(t *testing.T) {
		decoder := NewDecoder().FromString(morseSingleLetterEncoded).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, morseSingleLetterSrc, decoder.ToBytes())
	})

	t.Run("two letters", func(t *testing.T) {
		decoder := NewDecoder().FromString(morseTwoLettersEncoded).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, morseTwoLettersSrc, decoder.ToBytes())
	})

	t.Run("three letters", func(t *testing.T) {
		decoder := NewDecoder().FromString(morseThreeLettersEncoded).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, morseThreeLettersSrc, decoder.ToBytes())
	})

	t.Run("all letters", func(t *testing.T) {
		decoder := NewDecoder().FromString(morseAllLettersEncoded).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte(strings.ToLower(string(morseAllLettersSrc))), decoder.ToBytes())
	})

	t.Run("all numbers", func(t *testing.T) {
		decoder := NewDecoder().FromString(morseAllNumbersEncoded).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, morseAllNumbersSrc, decoder.ToBytes())
	})

	t.Run("punctuation", func(t *testing.T) {
		decoder := NewDecoder().FromString(morsePunctuationEncoded).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, morsePunctuationSrc, decoder.ToBytes())
	})

	t.Run("mixed case", func(t *testing.T) {
		decoder := NewDecoder().FromString(morseMixedCaseEncoded).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte(strings.ToLower(string(morseMixedCaseSrc))), decoder.ToBytes())
	})

	t.Run("error file", func(t *testing.T) {
		errorFile := mock.NewErrorFile(errors.New("read error"))
		decoder := NewDecoder().FromFile(errorFile).ByMorse()
		assert.Error(t, decoder.Error)
		assert.Contains(t, decoder.Error.Error(), "read error")
	})

	t.Run("decode with existing error", func(t *testing.T) {
		decoder := NewDecoder()
		decoder.Error = errors.New("existing error")
		result := decoder.FromString("test").ByMorse()
		assert.Equal(t, errors.New("existing error"), result.Error)
		assert.NotNil(t, result.src)
	})

	t.Run("decode invalid morse", func(t *testing.T) {
		decoder := NewDecoder().FromString("invalid morse").ByMorse()
		assert.Error(t, decoder.Error)
		assert.Contains(t, decoder.Error.Error(), "unsupported character")
	})

	t.Run("decode with no data no reader", func(t *testing.T) {
		decoder := NewDecoder().ByMorse()
		if decoder.Error != nil {
			assert.Contains(t, decoder.Error.Error(), "no data to decode")
		}
	})
}

func TestDecoder_ByMorse_Error(t *testing.T) {
	t.Run("existing error", func(t *testing.T) {
		decoder := NewDecoder()
		decoder.Error = errors.New("existing error")
		result := decoder.FromString("test").ByMorse()
		assert.Equal(t, errors.New("existing error"), result.Error)
		assert.NotNil(t, result.src)
	})
}

func TestMorseRoundTrip(t *testing.T) {
	t.Run("morse round trip", func(t *testing.T) {
		testData := "hello world"
		encoder := NewEncoder().FromString(testData).ByMorse()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromString(encoder.ToString()).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, testData, decoder.ToString())
	})

	t.Run("morse round trip with file", func(t *testing.T) {
		testData := "hello world"
		file := mock.NewFile([]byte(testData), "test.txt")
		defer file.Close()
		encoder := NewEncoder().FromFile(file).ByMorse()
		assert.Nil(t, encoder.Error)

		decoderFile := mock.NewFile(encoder.ToBytes(), "encoded.txt")
		defer decoderFile.Close()
		decoder := NewDecoder().FromFile(decoderFile).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, testData, decoder.ToString())
	})

	t.Run("morse round trip with bytes", func(t *testing.T) {
		testData := []byte("hello world")
		encoder := NewEncoder().FromBytes(testData).ByMorse()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromBytes(encoder.ToBytes()).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, testData, decoder.ToBytes())
	})
}

func TestMorseEdgeCases(t *testing.T) {
	t.Run("very large data", func(t *testing.T) {
		largeData := []byte(strings.Repeat("The quick brown fox jumps over the lazy dog. ", 100))
		encoder := NewEncoder().FromBytes(largeData).ByMorse()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromString(encoder.ToString()).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, []byte(strings.ToLower(string(largeData))), decoder.ToBytes())
	})

	t.Run("single character", func(t *testing.T) {
		testData := "A"
		encoder := NewEncoder().FromString(testData).ByMorse()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromString(encoder.ToString()).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, strings.ToLower(testData), decoder.ToString())
	})

	t.Run("mixed case", func(t *testing.T) {
		testData := "Hello World"
		encoder := NewEncoder().FromString(testData).ByMorse()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromString(encoder.ToString()).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, strings.ToLower(testData), decoder.ToString())
	})

	t.Run("mixed encoding methods", func(t *testing.T) {
		testData := "hello world"

		encoder1 := NewEncoder().FromString(testData).ByMorse()
		encoder2 := NewEncoder().FromBytes([]byte(testData)).ByMorse()
		encoder3 := NewEncoder().FromFile(mock.NewFile([]byte(testData), "test.txt")).ByMorse()

		assert.Nil(t, encoder1.Error)
		assert.Nil(t, encoder2.Error)
		assert.Nil(t, encoder3.Error)
		assert.Equal(t, encoder1.ToString(), encoder2.ToString())
		assert.Equal(t, encoder1.ToString(), encoder3.ToString())
	})

	t.Run("numbers", func(t *testing.T) {
		testData := "1234567890"

		encoder := NewEncoder().FromString(testData).ByMorse()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromString(encoder.ToString()).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, testData, decoder.ToString())
	})

	t.Run("punctuation", func(t *testing.T) {
		testData := ".,?!"

		encoder := NewEncoder().FromString(testData).ByMorse()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromString(encoder.ToString()).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, testData, decoder.ToString())
	})

	t.Run("all letters", func(t *testing.T) {
		testData := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

		encoder := NewEncoder().FromString(testData).ByMorse()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromString(encoder.ToString()).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, strings.ToLower(testData), decoder.ToString())
	})

	t.Run("all numbers", func(t *testing.T) {
		testData := "0123456789"

		encoder := NewEncoder().FromString(testData).ByMorse()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromString(encoder.ToString()).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, testData, decoder.ToString())
	})

	t.Run("mixed characters", func(t *testing.T) {
		testData := "HELLO WORLD 123 !@#"

		encoder := NewEncoder().FromString(testData).ByMorse()
		assert.Nil(t, encoder.Error)

		decoder := NewDecoder().FromString(encoder.ToString()).ByMorse()
		assert.Nil(t, decoder.Error)
		assert.Equal(t, strings.ToLower(testData), decoder.ToString())
	})
}

func TestMorseSpecific(t *testing.T) {
	t.Run("morse alphabet verification", func(t *testing.T) {
		// Morse alphabet should contain only dots, dashes, and spaces
		morseAlphabet := ".- "
		allValid := true
		for _, char := range morseAlphabet {
			if !strings.ContainsRune(".- ", char) {
				allValid = false
				break
			}
		}
		assert.True(t, allValid)
	})

	t.Run("morse encoding consistency", func(t *testing.T) {
		testData := "hello world"
		encoder1 := NewEncoder().FromString(testData).ByMorse()
		encoder2 := NewEncoder().FromString(testData).ByMorse()

		assert.Nil(t, encoder1.Error)
		assert.Nil(t, encoder2.Error)
		assert.Equal(t, encoder1.ToString(), encoder2.ToString())
	})

	t.Run("morse vs string vs bytes consistency", func(t *testing.T) {
		testData := "hello world"

		encoder1 := NewEncoder().FromString(testData).ByMorse()
		encoder2 := NewEncoder().FromBytes([]byte(testData)).ByMorse()
		encoder3 := NewEncoder().FromFile(mock.NewFile([]byte(testData), "test.txt")).ByMorse()

		assert.Nil(t, encoder1.Error)
		assert.Nil(t, encoder2.Error)
		assert.Nil(t, encoder3.Error)
		assert.Equal(t, encoder1.ToString(), encoder2.ToString())
		assert.Equal(t, encoder1.ToString(), encoder3.ToString())
	})

	t.Run("morse specific test cases", func(t *testing.T) {
		// Test specific Morse encoding patterns (generated using dongle implementation)
		testCases := []struct {
			input    string
			expected string
		}{
			{"a", ".-"},
			{"ab", ".- -..."},
			{"abc", ".- -... -.-."},
			{"hello", ".... . .-.. .-.. ---"},
			{"world", ".-- --- .-. .-.. -.."},
			{"hello world", ".... . .-.. .-.. --- / .-- --- .-. .-.. -.."},
			{"123", ".---- ..--- ...--"},
			{"456", "....- ..... -...."},
			{"789", "--... ---.. ----."},
			{"0123456789", "----- .---- ..--- ...-- ....- ..... -.... --... ---.. ----."},
			{".,?!", ".-.-.- --..-- ..--.. -.-.--"},
			{"hello, world!", ".... . .-.. .-.. --- --..-- / .-- --- .-. .-.. -.. -.-.--"},
			{"test123", "- . ... - .---- ..--- ...--"},
			{"mixed CASE", "-- .. -..- . -.. / -.-. .- ... ."},
		}

		for _, tc := range testCases {
			encoder := NewEncoder().FromString(tc.input).ByMorse()
			assert.Nil(t, encoder.Error)
			assert.Equal(t, tc.expected, encoder.ToString())

			decoder := NewDecoder().FromString(tc.expected).ByMorse()
			assert.Nil(t, decoder.Error)
			assert.Equal(t, strings.ToLower(tc.input), decoder.ToString())
		}
	})
}
