import numpy as np
from sklearn.mixture import GaussianMixture
import logging as log
import traceback as tb
import datetime as dt
from math import exp

class TriangleVariableProfiler():
    def __init__(self, memory, buffer_size):
        self.memory = memory
        self.buffer_size = buffer_size
        self.median = None
        self.buffer = []

    def predict(self, x):
        try:
            if self.median is None:
                return 0.5
            else:
                p = 1.0 - abs(( x / self.median ) - 1.0)
                return max(p, 0.0)
        except Exception as exc:
            log.error("Error predicting in uniformVariableProfiler: {0}".format(exc))
            return 0.5
        
    def profile(self, x):
        try:
            distribution_reestimated = False
            if len(self.buffer) >= self.buffer_size:
                self.estimate_distribution()
                self.buffer.clear()
                self.buffer.append(x)
                distribution_reestimated = True
            return distribution_reestimated
        except Exception as exc:
            log.error("Error profiling in uniformVariableProfiler: {0}".format(exc))
            return False

    def estimate_distribution(self):
        try:
            new_median = np.median(np.array(self.buffer))
            if self.median is None:
                self.median = new_median
            else:
                self.median = self.memory * self.median + ( 1 - self.memory ) * new_median
        except Exception as exc:
            log.error("Error calculating median: {0}".format(exc))


class IntegerVaribleProfiler():
    def __init__(self, memory, buffer_size):
        self.memory = memory
        self.buffer_size = buffer_size
        self.initialized = False
        self.probs = {}
        self.buffer = []

    def predict(self, x):
        try:
            if not self.initialized:
                return 0.5
            if x in self.probs:
                return self.probs[x]
            else:
                return 0.0
        except Exception as exc:
            log.error("Error predicting probabilities in integerVariableProfiler: {0}".format(exc))

    def profile(self, x):
        try:
            if len(self.buffer) >= self.buffer_size:
                self.estimate_distribution()
                self.buffer.clear()
                self.initialized = True
            self.buffer.append(x)
        except Exception as exc:
            log.error("Error profiling in integerVariableProfiler: {0}".format(exc))

    def estimate_distribution(self):
        try:
            for val in self.probs:
                self.probs[val] = self.memory * self.probs[val]

            values, counts = np.unique(np.array(self.buffer), return_counts=True)
            new_probs = counts / counts.sum()

            for i, val in enumerate(values):
                if val in self.probs:
                    self.probs[val] += (1-self.memory) * new_probs[i]
                else:
                    if self.initialized:
                        self.probs[val] = (1-self.memory) * new_probs[i]
                    else: 
                        self.probs[val] = new_probs[i]
        except Exception as exc:
            log.error(f"Error estimating probabilities in integerVariableProfiler: {exc}\n{tb.format_exc()}")

        try:
            to_del = [val for val in self.probs if self.probs[val] < 1e-9]
            for val in to_del: del self.probs[val]
        except Exception as exc:
            log.error("Error collecting garbage in integerVariableProfiler: {0}".format(exc))

        try:
            prob_sum = sum([p for p in self.probs.values()])
            for val in self.probs:
                self.probs[val] /= prob_sum
        except Exception as exc:
            log.error("Error normalizing probabilities in integerVariableProfiler: {0}".format(exc))


class NormalVariableProfiler():
    def __init__(self, memory, buffer_size, n_components):
        self.memory = memory
        self.buffer_size = buffer_size
        self.initialized = False
        self.gmm = GaussianMixture(n_components=n_components,
                                   covariance_type="spherical",
                                   warm_start=True, max_iter=100)
        self.buffer = []

    def predict(self, x):
        try:
            if not self.initialized:
                return 0.5
            else:
                x = np.array([[x]])
                p = np.exp(self.gmm.score_samples(x))
                return p.item()
        except Exception as exc:
            log.error("Error predicting in NormalVariableProfiler: {0}".format(exc))

    def profile(self, x):
        try:
            if len(self.buffer) >= self.buffer_size:
                self.estimate_distribution()
                self.buffer.clear()
                self.initialized = True
            self.buffer.append(x)
        except Exception as exc:
            log.error("Error profiling in NormalVariableProfiler: {0}".format(exc))

    def estimate_distribution(self):
        try:
            if self.initialized:
                old_weights = self.gmm.weights_
                old_covariances = self.gmm.covariances_
                old_means = self.gmm.means_

            x = np.array(self.buffer).reshape(-1, 1)
            self.gmm = self.gmm.fit(x)
            self.gmm.covariances_ += 1e-4

            if self.initialized:
                self.gmm.weights_ = self.memory * old_weights + (1-self.memory) * self.gmm.weights_
                self.gmm.covariances_ = self.memory * old_covariances + (1-self.memory) * self.gmm.covariances_
                self.gmm.means_ = self.memory * old_means + (1-self.memory) * self.gmm.means_
        except Exception as exc:
            log.error("Error estimating distribution in NormalVariableProfiler: {0}".format(exc))

        try:
            self.gmm.weights_ = self.gmm.weights_ / self.gmm.weights_.sum()
        except Exception as exc:
            log.error("Error normalizing in NormalVariableProfiler: {0}".format(exc))

    def get_mean(self):
        if self.initialized:
            return self.gmm.means_.item()
        else:
            return None


class LogNormalVariableProfiler(NormalVariableProfiler):
    def __init__(self, memory, buffer_size, n_components):
        super(LogNormalVariableProfiler, self).__init__(memory, buffer_size, n_components)

    def predict(self, x):
        x = max(x, 1e-9)
        x = np.log(x)
        return super().predict(x)

    def profile(self, x):
        x = max(x, 1e-9)
        x = np.log(x)
        super().profile(x)

    def get_mean(self):
        median = super().get_mean()
        if median:
            return np.exp(median)
        else:
            return None
