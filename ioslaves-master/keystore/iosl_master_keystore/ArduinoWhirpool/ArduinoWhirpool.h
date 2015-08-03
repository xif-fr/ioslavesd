/**
 * Arduino implemantation of the Whirlpool hashing function.
 * Based on LibreSSL implementation.
 *
 * The Whirlpool algorithm was developed by
 *  Paulo S. L. M. Barreto <pbarreto@scopus.com.br>
 *  Vincent Rijmen <vincent.rijmen@cryptomathic.com>
 *
 * See
 *      P.S.L.M. Barreto, V. Rijmen,
 *      `The Whirlpool hashing function,'
 *      NESSIE submission, 2000 (tweaked version, 2001),
 *      https://www.cosic.esat.kuleuven.ac.be/nessie/workshop/submissions/whirlpool.zip
 *
 * Based on "@version 3.0 (2003.03.12)" by Paulo S.L.M. Barreto and Vincent Rijmen. 
 * Lookup "reference implementations" on http://planeta.terra.com.br/informatica/paulobarreto/
 *
 * =============================================================================
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef ARDUINO_WHIRPOOL_HPP
#define ARDUINO_WHIRPOOL_HPP

#include <inttypes.h>
#include <string.h>

#define WHIRLPOOL_DIGEST_LENGTH 64
#define WHIRLPOOL_BLOCK 64
#define WHIRLPOOL_COUNTER 32

namespace whirpool {
	
	union u64o { 
		uint8_t c [WHIRLPOOL_DIGEST_LENGTH];
		uint64_t q [WHIRLPOOL_DIGEST_LENGTH/sizeof(uint64_t)];
	};
	
		// Context
	struct ctx_t {
		union u64o	H;
		unsigned char	data [64];
		unsigned int	byteoff;
		size_t		bitlen [WHIRLPOOL_COUNTER/sizeof(size_t)];
	};
	
		// Initialize/reset the context.
	void init (struct whirpool::ctx_t*);
		// Feed the hashing function with data. Max 4096 bytes.
	void update (struct whirpool::ctx_t*, const void* data, size_t sz);
		// Finalize the hashing operation. Digest is whirpool::ctx_t::H::c. Context need to be reset for further reusing.
	void final (struct whirpool::ctx_t*);
}

#endif
