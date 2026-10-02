<?php
/**
 * Minimal dependency-injection container.
 *
 * @package TotalSecurityWP
 */

namespace TotalSecurityWP;

defined( 'ABSPATH' ) || exit;

/**
 * A small service container supporting transient bindings, shared singletons,
 * and pre-built instances. Intentionally tiny — no reflection, no autowiring.
 */
class Container {

	/**
	 * Factory closures keyed by service id.
	 *
	 * @var array<string, callable>
	 */
	private array $factories = array();

	/**
	 * Service ids that should be resolved once and cached.
	 *
	 * @var array<string, bool>
	 */
	private array $shared = array();

	/**
	 * Resolved instances cache.
	 *
	 * @var array<string, mixed>
	 */
	private array $instances = array();

	/**
	 * Register a shared (singleton) binding.
	 *
	 * @param string   $id      Service identifier.
	 * @param callable $factory Factory receiving the container.
	 */
	public function singleton( string $id, callable $factory ): void {
		$this->factories[ $id ] = $factory;
		$this->shared[ $id ]    = true;
	}

	/**
	 * Register a transient binding (new instance per resolution).
	 *
	 * @param string   $id      Service identifier.
	 * @param callable $factory Factory receiving the container.
	 */
	public function bind( string $id, callable $factory ): void {
		$this->factories[ $id ] = $factory;
		$this->shared[ $id ]    = false;
	}

	/**
	 * Register an already-constructed instance as a shared service.
	 *
	 * @param string $id     Service identifier.
	 * @param mixed  $object The instance.
	 */
	public function instance( string $id, $object ): void {
		$this->instances[ $id ] = $object;
		$this->shared[ $id ]    = true;
	}

	/**
	 * Whether a service is known to the container.
	 *
	 * @param string $id Service identifier.
	 */
	public function has( string $id ): bool {
		return isset( $this->factories[ $id ] ) || isset( $this->instances[ $id ] );
	}

	/**
	 * Resolve a service.
	 *
	 * @param string $id Service identifier.
	 * @return mixed
	 * @throws \RuntimeException When the id is not bound.
	 */
	public function make( string $id ) {
		if ( isset( $this->instances[ $id ] ) ) {
			return $this->instances[ $id ];
		}

		if ( ! isset( $this->factories[ $id ] ) ) {
			throw new \RuntimeException( sprintf( 'Service "%s" is not bound in the container.', esc_html( $id ) ) );
		}

		$object = ( $this->factories[ $id ] )( $this );

		if ( ! empty( $this->shared[ $id ] ) ) {
			$this->instances[ $id ] = $object;
		}

		return $object;
	}
}
