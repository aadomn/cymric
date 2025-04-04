# Implementations of Cymric authenticated encryption modes

## Cymric
Cymric is a family of two authenticated encryption modes, namely Cymric1 and Cymric2, finely tuned for very short inputs.
While [the Manx modes](https://github.com/aadomn/manx_ae) (also named after a cat breed with short tail) already provide an efficient solution for this use case, Cymric adds an extra block cipher call to achieve beyond-birthday-bound (BBB) security.

| AE modes   | BC calls | Keys  | Security bits |
| :--------: | :------: | :---: | :-----------: |
| Manx       |     2    |   1   |     $n/2$     |
| Cymric     |     3    |   2   |      $n$      |

More specifically, Cymric1 achieves n-bit security but further limit the restrictions on the inputs' length.

| AE modes   | Security bits |                            Restrictions on inputs                               |
| :--------: | :-----------: | --------------------------------------------------------------------------------|
| Cymric1    |      $n$      | $\vert N \vert + \vert A \vert < n$ and $\vert M \vert + \vert N \vert \leq n$  |
| Cymric2    |     $2n/3$    | $\vert N \vert + \vert A \vert < n$ and $\vert M \vert \leq n$                  |

For more details, see the paper Cymric: Short-tailed but Mighty by Wonseok Choi, Yeongmin Lee, Kazuhiko Minematsu, Yusuke Naito and myself.

## Cipher-agnostic implementations

The Cymric implementations provided in this repository are cipher-agnostic in the sense that the internal functions related to the underlying block cipher (i.e. key expansion and block encryption) are passed as arguments rather than being hardcoded.
This way, it is easy to instantiate Cymric with your favorite block cipher dynamically..

## Structure of the repository

The repository structure is as follows:

```
cymric
│
├───cymric
│   
├───cymric-aes128
│   ├───armv7m
│   ├───avr8
│   └───x86_64
│   
├───cymric-gift128
│   ├───armv7m
│   └───avr8
│   
├───manx-lea128
│   ├───armv7m
│   └───avr8
```

The `cymric` folder contains the generic implementations of Cymric1 and Cymric2: instructions on how to plug your favorite block cipher are given in the folder-specific README.
The `cymric-aes128` folder contains implementations of Cymric1 and Cymric2 instantiated with different AES implementations listed by platform. See the folder-specific README files for more information.

## License

The code related to the Cymric AE modes released in this repository is under [CC0 license](https://creativecommons.org/publicdomain/zero/1.0/deed.en).
However, some block cipher implementations included in this repository might be under other licenses. If so, a folder-specific LICENSE file will be included. For instance, the AES implementations on AVR are based on [the work from B. Poettering](http://point-at-infinity.org/avraes/) which is under the [GNU General Public License](https://www.gnu.org/licenses/gpl-3.0.html).

## Patent-free notice
The authors are not aware of any patent convering the Cymric authenticated modes and do not intend to assert any patent claims in the future to promote wider adoption.