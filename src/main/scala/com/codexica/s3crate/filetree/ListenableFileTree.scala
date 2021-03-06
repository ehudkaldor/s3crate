package com.codexica.s3crate.filetree

/**
 * Simply generates a set of paths that should be inspected.
 *
 * @author Josh Albrecht (joshalbrecht@gmail.com)
 */
trait ListenableFileTree {
  def listen(): PathGenerator
}
